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

import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;

import org.jboss.logging.Logger;
import org.keycloak.authentication.CredentialRegistrator;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.managers.BruteForceProtector;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Map;
import jakarta.ws.rs.core.Response;

public class PhoneValidationRequiredAction implements RequiredActionProvider, CredentialRegistrator {
	private static final Logger logger = Logger.getLogger(PhoneValidationRequiredAction.class);
	public static final String PROVIDER_ID = "phone_validation_config";

	@Override
	public void evaluateTriggers(RequiredActionContext context) {
	}

	@Override
	public void requiredActionChallenge(RequiredActionContext context) {
		context.getAuthenticationSession().addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
		try {
			UserModel user = context.getUser();
			RealmModel realm = context.getRealm();

			AuthenticationSessionModel authSession = context.getAuthenticationSession();
			// TODO: get the alias from somewhere else or move config into realm or application scope
			AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
			if (config == null || config.getConfig() == null) {
				logger.error("No authenticator config alias 'sms-2fa' found; cannot send the validation SMS.");
				context.failure();
				return;
			}
			// Do not issue a new validation code to a user already locked out by brute-force protection.
			if (isDisabledByBruteForce(context)) {
				return;
			}

			String mobileNumber = authSession.getAuthNote("mobile_number");
			Map<String, String> cfg = config.getConfig();
			boolean maskPhoneInLogs = Boolean.parseBoolean(cfg.getOrDefault("maskPhoneNumberInLogs", "true"));
			logger.infof("Validating phone number: %s of user: %s", PhoneNumberLogMasker.forLog(mobileNumber, maskPhoneInLogs), user.getUsername());

			// Re-entry (page refresh / browser back): apply the same server-side limits as an explicit
			// resend, silently re-displaying the form when another send is not permitted. Without this,
			// refreshing the enrollment challenge triggers an unthrottled SMS send every time.
			if (authSession.getAuthNote(SmsCodeSender.NOTE_LAST_SENT_AT) != null) {
				if (SmsCodeSender.secondsUntilResendAllowed(authSession, SmsCodeSender.cooldownSeconds(cfg)) > 0
						|| SmsCodeSender.resendsUsed(authSession) >= SmsCodeSender.maxResendCount(cfg)) {
					context.challenge(smsForm(context, cfg).createForm(SmsAuthenticator.TPL_CODE));
					return;
				}
				authSession.setAuthNote(SmsCodeSender.NOTE_RESEND_COUNT,
					String.valueOf(SmsCodeSender.resendsUsed(authSession) + 1));
			}

			SmsCodeSender.sendCode(context.getSession(), realm, user, authSession, cfg, mobileNumber);

			context.challenge(smsForm(context, cfg).createForm(SmsAuthenticator.TPL_CODE));
		} catch (Exception e) {
			// See the resend path: the gateway host/URL is redacted at the throw site, so neither the
			// message nor the cause chain may be logged here.
			logger.error("SMS validation code send failed");
			context.failure();
		}
	}

	@Override
	public void processAction(RequiredActionContext context) {
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

		String enteredCode = context.getHttpRequest().getDecodedFormParameters().getFirst("code");

		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String mobileNumber = authSession.getAuthNote("mobile_number");
		String code = authSession.getAuthNote("code");
		String ttl = authSession.getAuthNote("ttl");

		if (code == null || ttl == null || enteredCode == null) {
			logger.warn("Phone number is not set");
			handleInvalidSmsCode(context);
			return;
		}

		boolean isValid = java.security.MessageDigest.isEqual(
			code.getBytes(java.nio.charset.StandardCharsets.UTF_8),
			enteredCode.getBytes(java.nio.charset.StandardCharsets.UTF_8));
		if (isValid && Long.parseLong(ttl) > System.currentTimeMillis()) {
			// valid
			SmsAuthCredentialProvider smnp = (SmsAuthCredentialProvider) context.getSession().getProvider(CredentialProvider.class, "mobile-number");
			if (!smnp.isConfiguredFor(context.getRealm(), context.getUser(), SmsAuthCredentialModel.TYPE)) {
				smnp.createCredential(context.getRealm(), context.getUser(), SmsAuthCredentialModel.createSmsAuthenticator(mobileNumber));
			} else {
				smnp.updateCredential(
					context.getRealm(),
					context.getUser(),
					new UserCredentialModel("random_id", "mobile-number", mobileNumber)
				);
			}
			context.getAuthenticationSession().removeRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
			handlePhoneToAttribute(context, mobileNumber);
			context.success();
		} else {
			// A genuinely wrong code counts toward brute-force lockout (parity with the login SMS
			// challenge); an expired-but-correct code does not — it is not a credential guess.
			if (!isValid) {
				recordBruteForceFailure(context);
			}
			handleInvalidSmsCode(context);
		}
	}

	/**
	 * Returns true (and fails the action) if brute-force protection has temporarily disabled the user —
	 * mirrors SmsAuthenticator so the enrollment SMS-validation step can't be guessed without limit.
	 */
	private boolean isDisabledByBruteForce(RequiredActionContext context) {
		RealmModel realm = context.getRealm();
		UserModel user = context.getUser();
		if (realm.isBruteForceProtected() && user != null
				&& context.getSession().getProvider(BruteForceProtector.class)
					.isTemporarilyDisabled(context.getSession(), realm, user)) {
			context.getEvent().user(user).error(Errors.USER_TEMPORARILY_DISABLED);
			context.failure();
			return true;
		}
		return false;
	}

	/**
	 * Records a failed enrollment-validation attempt with the realm brute-force protector so repeated
	 * wrong codes count toward lockout. The SMS code is reported under the "otp" category
	 * ({@link SmsCodeSender#BRUTE_FORCE_CATEGORIES}) because Keycloak (>= 26.7) only counts failures in
	 * an allow-list of categories; a null or other category would not be counted.
	 */
	private void recordBruteForceFailure(RequiredActionContext context) {
		RealmModel realm = context.getRealm();
		UserModel user = context.getUser();
		if (realm.isBruteForceProtected() && user != null) {
			context.getSession().getProvider(BruteForceProtector.class)
				.failedLogin(realm, user, context.getConnection(), context.getUriInfo(), SmsCodeSender.BRUTE_FORCE_CATEGORIES);
		}
	}

	private void handlePhoneToAttribute(RequiredActionContext context, String mobileNumber) {
		AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
		if (config == null) {
			logger.warn("No config alias sms-2fa found, skip phone number to attribute check");
		} else {
			if (Boolean.parseBoolean(config.getConfig().get("storeInAttribute"))) {
				context.getUser().setSingleAttribute("mobile_number", mobileNumber);
			}
		}
	}

	/**
	 * Handles a resend request from the enrollment code-entry form. Mirrors
	 * SmsAuthenticator.handleResend: business-configurable ceiling and cooldown enforced
	 * server-side; a permitted resend rotates the code and re-sends it; resend attempts
	 * never touch the brute-force counters.
	 */
	private void handleResend(RequiredActionContext context) {
		AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
		if (config == null || config.getConfig() == null
				|| config.getConfig().get("length") == null || config.getConfig().get("ttl") == null) {
			logger.error("No usable authenticator config alias 'sms-2fa' found; cannot resend the validation SMS.");
			context.failure();
			return;
		}
		Map<String, String> cfg = config.getConfig();
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		String mobileNumber = authSession.getAuthNote("mobile_number");
		if (mobileNumber == null) {
			logger.warn("Phone number is not set; cannot resend the validation SMS.");
			handleInvalidSmsCode(context);
			return;
		}

		int used = SmsCodeSender.resendsUsed(authSession);
		int max = SmsCodeSender.maxResendCount(cfg);
		if (used >= max) {
			// The security signal worth auditing/alerting on: someone keeps requesting codes past the ceiling.
			logger.warnf("SMS resend limit reached during enrollment for user %s (%d/%d)",
				context.getUser().getUsername(), used, max);
			context.getEvent().user(context.getUser()).error("sms_resend_limit_exceeded");
			context.challenge(smsForm(context, cfg).setError("smsAuthResendLimitReached")
				.createForm(SmsAuthenticator.TPL_CODE));
			return;
		}

		long wait = SmsCodeSender.secondsUntilResendAllowed(authSession, SmsCodeSender.cooldownSeconds(cfg));
		if (wait > 0) {
			// No send, no brute-force interaction, no event — a double-click must not spam the event log.
			context.challenge(smsForm(context, cfg)
				.setError("smsAuthResendTooSoon", String.valueOf(wait))
				.createForm(SmsAuthenticator.TPL_CODE));
			return;
		}

		try {
			// Burn the resend allowance before the attempt: a failing gateway must not hand out free
			// retries, or the ceiling never engages and the send loop is unbounded.
			authSession.setAuthNote(SmsCodeSender.NOTE_RESEND_COUNT, String.valueOf(used + 1));
			SmsCodeSender.sendCode(context.getSession(), context.getRealm(), context.getUser(),
				authSession, cfg, mobileNumber);
			context.getEvent().detail("sms_resend_count", String.valueOf(used + 1));
			logger.infof("SMS validation code resent for user %s (resend %d of %d)",
				context.getUser().getUsername(), used + 1, max);
			context.challenge(smsForm(context, cfg).setInfo("smsAuthCodeResent")
				.createForm(SmsAuthenticator.TPL_CODE));
		} catch (Exception e) {
			// Message and cause chain stay out of the log: ApiSmsService deliberately redacts the
			// gateway host/URL from what it throws, and echoing them here would defeat that.
			logger.error("SMS validation code resend failed");
			context.failure();
		}
	}

	/**
	 * Code-entry form pre-loaded with the resend state the template needs: how many resends remain
	 * (0 hides the button) and the seconds left on the cooldown (drives the cosmetic countdown).
	 */
	private LoginFormsProvider smsForm(RequiredActionContext context, Map<String, String> cfg) {
		AuthenticationSessionModel authSession = context.getAuthenticationSession();
		return context.form()
			.setAttribute("realm", context.getRealm())
			.setAttribute(SmsCodeSender.ATTR_RESEND_REMAINING,
				Math.max(0, SmsCodeSender.maxResendCount(cfg) - SmsCodeSender.resendsUsed(authSession)))
			.setAttribute(SmsCodeSender.ATTR_RESEND_WAIT,
				SmsCodeSender.secondsUntilResendAllowed(authSession, SmsCodeSender.cooldownSeconds(cfg)));
	}

	private void handleInvalidSmsCode(RequiredActionContext context) {
		AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
		Map<String, String> cfg = config == null ? null : config.getConfig();
		Response challenge = smsForm(context, cfg)
			.setError("smsAuthCodeInvalid")
			.createForm(SmsAuthenticator.TPL_CODE);
		context.challenge(challenge);
	}

	@Override
	public void close() {
	}

	@Override
	public String getCredentialType(KeycloakSession keycloakSession, AuthenticationSessionModel authenticationSessionModel) {
		return SmsAuthCredentialModel.TYPE;
	}
}
