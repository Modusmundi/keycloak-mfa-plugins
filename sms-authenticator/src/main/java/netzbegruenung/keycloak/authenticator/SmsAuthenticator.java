/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author Niko Köbler, https://www.n-k.de, @dasniko
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 */

package netzbegruenung.keycloak.authenticator;

import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialData;
import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import netzbegruenung.keycloak.authenticator.gateway.SmsServiceFactory;

import org.jboss.logging.Logger;
import org.keycloak.authentication.CredentialValidator;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.services.messages.Messages;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;

import jakarta.ws.rs.core.Response;
import java.util.Map;
import java.util.Optional;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class SmsAuthenticator implements Authenticator, CredentialValidator<SmsAuthCredentialProvider> {

	private static final Logger logger = Logger.getLogger(SmsAuthenticator.class);
	static final String TPL_CODE = "login-sms.ftl";

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		KeycloakSession session = context.getSession();
		UserModel user = context.getUser();
		RealmModel realm = context.getRealm();

		// Do not issue a new code to a user already locked out by brute-force protection.
		if (isDisabledByBruteForce(context)) {
			return;
		}

		String mobileNumber;
		try {
			mobileNumber = mobileNumber(context);
		} catch (IOException e1) {
			logger.warn(e1.getMessage(), e1);
			return;
		}

		// Fail cleanly (not with a 500/NPE) if this execution has no authenticator config — e.g. the SMS
		// authenticator was added to the flow without an 'sms-2fa' config, so length/ttl are absent.
		if (config == null || config.getConfig() == null
				|| config.getConfig().get("length") == null || config.getConfig().get("ttl") == null) {
			logger.error("SMS authenticator is missing its configuration (length/ttl); add an authenticator config to the flow execution.");
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().setError("smsAuthSmsNotSent", "Error. Use another method.")
					.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			return;
		}

		Map<String, String> cfg = config.getConfig();
		AuthenticationSessionModel authSession = context.getAuthenticationSession();

		// Re-entry (page refresh / browser back): apply the same server-side limits as an explicit
		// resend, silently re-displaying the form when another send is not permitted. Without this,
		// refreshing the challenge page triggers an unthrottled SMS send every time.
		if (authSession.getAuthNote(SmsCodeSender.NOTE_LAST_SENT_AT) != null) {
			if (SmsCodeSender.secondsUntilResendAllowed(authSession, SmsCodeSender.cooldownSeconds(cfg)) > 0
					|| SmsCodeSender.resendsUsed(authSession) >= SmsCodeSender.maxResendCount(cfg)) {
				context.challenge(smsForm(context, cfg).createForm(TPL_CODE));
				return;
			}
			authSession.setAuthNote(SmsCodeSender.NOTE_RESEND_COUNT,
				String.valueOf(SmsCodeSender.resendsUsed(authSession) + 1));
		}

		try {
			SmsCodeSender.sendCode(session, realm, user, authSession, cfg, mobileNumber);
			context.challenge(smsForm(context, cfg).createForm(TPL_CODE));
		} catch (Exception e) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().setError("smsAuthSmsNotSent", "Error. Use another method.")
					.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		// Reject further attempts once brute-force protection has temporarily disabled the account.
		if (isDisabledByBruteForce(context)) {
			return;
		}

		// Resend requests are handled before any code validation: the resend button posts the form
		// with an empty code, which must never be treated as a guess.
		if (context.getHttpRequest().getDecodedFormParameters().containsKey(SmsCodeSender.FORM_PARAM_RESEND)) {
			handleResend(context);
			return;
		}

		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		Map<String, String> cfg = config == null ? null : config.getConfig();

		String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");

		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String code = authSession.getAuthNote("code");
		String ttl = authSession.getAuthNote("ttl");

		if (code == null || ttl == null) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			return;
		}

		// No code submitted (missing/blank 'code' form param, e.g. a malformed POST): re-prompt instead
		// of dereferencing null. Not counted as a brute-force failure — an empty submission is not a
		// credential guess, and counting it would let blank posts lock a user out.
		if (enteredCode == null || enteredCode.isBlank()) {
			context.challenge(smsForm(context, cfg).setError("smsAuthCodeInvalid").createForm(TPL_CODE));
			return;
		}

		boolean isValid = java.security.MessageDigest.isEqual(
			code.getBytes(java.nio.charset.StandardCharsets.UTF_8),
			enteredCode.getBytes(java.nio.charset.StandardCharsets.UTF_8));
		if (isValid) {
			if (Long.parseLong(ttl) < System.currentTimeMillis()) {
				// expired
				context.failureChallenge(AuthenticationFlowError.EXPIRED_CODE,
					context.form().setError("smsAuthCodeExpired").createErrorPage(Response.Status.BAD_REQUEST));
			} else {
				// valid
				context.success();
			}
		} else {
			// invalid
			context.getEvent().user(context.getUser()).error("invalid_user_credentials");
			// Record the failure with the realm brute-force protector so repeated wrong SMS codes are
			// rate-limited / locked out, the same way the built-in OTP form is protected.
			recordBruteForceFailure(context);
			Response challenge = smsForm(context, cfg)
				.setError("smsAuthCodeInvalid")
				.createForm(TPL_CODE);
			context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
		}
	}

	/**
	 * Handles a resend request from the code-entry form. Enforces the business-configurable
	 * per-session ceiling (resendMaxCount) and cooldown (resendCooldownSeconds) server-side;
	 * a permitted resend generates a fresh code (invalidating the previous one) and re-sends it.
	 * Resend attempts never touch the brute-force counters — they are not credential guesses.
	 */
	private void handleResend(AuthenticationFlowContext context) {
		AuthenticatorConfigModel config = context.getAuthenticatorConfig();
		if (config == null || config.getConfig() == null
				|| config.getConfig().get("length") == null || config.getConfig().get("ttl") == null) {
			logger.error("SMS authenticator is missing its configuration (length/ttl); cannot resend a code.");
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().setError("smsAuthSmsNotSent", "Error. Use another method.")
					.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
			return;
		}
		Map<String, String> cfg = config.getConfig();
		AuthenticationSessionModel authSession = context.getAuthenticationSession();

		int used = SmsCodeSender.resendsUsed(authSession);
		int max = SmsCodeSender.maxResendCount(cfg);
		if (used >= max) {
			// The security signal worth auditing/alerting on: someone keeps requesting codes past the ceiling.
			logger.warnf("SMS resend limit reached for user %s (%d/%d)", context.getUser().getUsername(), used, max);
			context.getEvent().user(context.getUser()).error("sms_resend_limit_exceeded");
			context.challenge(smsForm(context, cfg).setError("smsAuthResendLimitReached").createForm(TPL_CODE));
			return;
		}

		long wait = SmsCodeSender.secondsUntilResendAllowed(authSession, SmsCodeSender.cooldownSeconds(cfg));
		if (wait > 0) {
			// No send, no brute-force interaction, no event — a double-click must not spam the event log.
			context.challenge(smsForm(context, cfg)
				.setError("smsAuthResendTooSoon", String.valueOf(wait)).createForm(TPL_CODE));
			return;
		}

		try {
			SmsCodeSender.sendCode(context.getSession(), context.getRealm(), context.getUser(),
				authSession, cfg, mobileNumber(context));
			authSession.setAuthNote(SmsCodeSender.NOTE_RESEND_COUNT, String.valueOf(used + 1));
			// Rides the terminal LOGIN/LOGIN_ERROR event so resend usage is visible in the audit trail.
			context.getEvent().detail("sms_resend_count", String.valueOf(used + 1));
			logger.infof("SMS code resent for user %s (resend %d of %d)", context.getUser().getUsername(), used + 1, max);
			context.challenge(smsForm(context, cfg).setInfo("smsAuthCodeResent").createForm(TPL_CODE));
		} catch (Exception e) {
			context.failureChallenge(AuthenticationFlowError.INTERNAL_ERROR,
				context.form().setError("smsAuthSmsNotSent", "Error. Use another method.")
					.createErrorPage(Response.Status.INTERNAL_SERVER_ERROR));
		}
	}

	private String mobileNumber(AuthenticationFlowContext context) throws IOException {
		Optional<CredentialModel> model = context.getUser().credentialManager()
			.getStoredCredentialsByTypeStream(SmsAuthCredentialModel.TYPE).findFirst();
		return JsonSerialization.readValue(model.orElseThrow().getCredentialData(), SmsAuthCredentialData.class)
			.getMobileNumber();
	}

	/**
	 * Code-entry form pre-loaded with the resend state the template needs: how many resends remain
	 * (0 hides the button) and the seconds left on the cooldown (drives the cosmetic countdown).
	 */
	private LoginFormsProvider smsForm(AuthenticationFlowContext context, Map<String, String> cfg) {
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		return context.form()
			.setAttribute("realm", context.getRealm())
			.setAttribute(SmsCodeSender.ATTR_RESEND_REMAINING,
				Math.max(0, SmsCodeSender.maxResendCount(cfg) - SmsCodeSender.resendsUsed(authSession)))
			.setAttribute(SmsCodeSender.ATTR_RESEND_WAIT,
				SmsCodeSender.secondsUntilResendAllowed(authSession, SmsCodeSender.cooldownSeconds(cfg)));
	}

	@Override
	public boolean requiresUser() {
		return true;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return getCredentialProvider(session).isConfiguredFor(realm, user, getType(session));
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
		user.addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
	}

	public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
		return Collections.singletonList((PhoneNumberRequiredActionFactory)session.getKeycloakSessionFactory().getProviderFactory(RequiredActionProvider.class, PhoneNumberRequiredAction.PROVIDER_ID));
	}

	/**
	 * Returns true (and fails the flow) if brute-force protection has temporarily disabled the user.
	 * The stock SMS authenticator never consulted brute-force state, so SMS codes could be guessed
	 * without limit; this brings it in line with the built-in OTP form.
	 */
	private boolean isDisabledByBruteForce(AuthenticationFlowContext context) {
		RealmModel realm = context.getRealm();
		UserModel user = context.getUser();
		if (realm.isBruteForceProtected() && user != null
				&& context.getSession().getProvider(BruteForceProtector.class)
					.isTemporarilyDisabled(context.getSession(), realm, user)) {
			context.getEvent().user(user).error(Errors.USER_TEMPORARILY_DISABLED);
			context.failureChallenge(AuthenticationFlowError.USER_TEMPORARILY_DISABLED,
				context.form().setError(Messages.ACCOUNT_TEMPORARILY_DISABLED)
					.createErrorPage(Response.Status.UNAUTHORIZED));
			return true;
		}
		return false;
	}

	/**
	 * Records a failed second-factor attempt with the realm brute-force protector, mirroring the
	 * framework's own AuthenticationProcessor.logFailure() call so failures count toward lockout.
	 */
	private void recordBruteForceFailure(AuthenticationFlowContext context) {
		RealmModel realm = context.getRealm();
		UserModel user = context.getUser();
		if (realm.isBruteForceProtected() && user != null) {
			context.getSession().getProvider(BruteForceProtector.class).failedLogin(
				realm, user, context.getConnection(), context.getUriInfo(), SmsCodeSender.BRUTE_FORCE_CATEGORIES);
		}
	}

	@Override
	public void close() {
	}

	@Override
	public SmsAuthCredentialProvider getCredentialProvider(KeycloakSession session) {
		return (SmsAuthCredentialProvider)session.getProvider(CredentialProvider.class, SmsAuthCredentialProviderFactory.PROVIDER_ID);
	}
}
