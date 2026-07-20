/*
 * Copyright 2026 Frank Winston Crum
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package netzbegruenung.keycloak.authenticator;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.credential.CredentialModel;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.ThemeManager;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;
import org.keycloak.vault.VaultTranscriber;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Resend + rate-limit behavior of the login SMS challenge. Simulation mode is on in every
 * test, so "sending" is the logging lambda — a send is observable as a rotated "code" auth
 * note plus an updated "smsLastSentAt" note.
 */
public class SmsAuthenticatorResendTest {

	private SmsAuthenticator authenticator;
	private AuthenticationFlowContext context;
	private AuthenticationSessionModel authSession;
	private HttpRequest request;
	private LoginFormsProvider form;
	private RealmModel realm;
	private KeycloakSession session;
	private UserModel user;
	private EventBuilder event;
	private Map<String, String> configMap;
	private Map<String, String> notes;

	@BeforeEach
	public void setup() throws Exception {
		authenticator = new SmsAuthenticator();
		context = mock(AuthenticationFlowContext.class);
		authSession = mock(AuthenticationSessionModel.class);
		request = mock(HttpRequest.class);
		form = mock(LoginFormsProvider.class, org.mockito.Mockito.RETURNS_SELF);
		realm = mock(RealmModel.class);
		session = mock(KeycloakSession.class);
		user = mock(UserModel.class);
		event = mock(EventBuilder.class);

		when(context.getAuthenticationSession()).thenReturn(authSession);
		when(context.getHttpRequest()).thenReturn(request);
		when(context.form()).thenReturn(form);
		when(context.getRealm()).thenReturn(realm);
		when(context.getSession()).thenReturn(session);
		when(context.getUser()).thenReturn(user);
		when(context.getEvent()).thenReturn(event);
		when(event.user(any(UserModel.class))).thenReturn(event);
		when(event.detail(anyString(), anyString())).thenReturn(event);

		// Brute-force protection off: the resend paths must never consult the protector anyway.
		when(realm.isBruteForceProtected()).thenReturn(false);

		// Map-backed auth notes so code rotation and counters are observable.
		notes = new HashMap<>();
		doAnswer(i -> notes.put(i.getArgument(0), i.getArgument(1)))
			.when(authSession).setAuthNote(anyString(), anyString());
		when(authSession.getAuthNote(anyString())).thenAnswer(i -> notes.get(i.getArgument(0)));
		doAnswer(i -> notes.remove(i.getArgument(0)))
			.when(authSession).removeAuthNote(anyString());

		// Stored mobile-number credential (fresh stream per call).
		CredentialModel credential = new CredentialModel();
		credential.setType(netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel.TYPE);
		credential.setCredentialData("{\"mobileNumber\":\"+15555550100\"}");
		SubjectCredentialManager credentialManager = mock(SubjectCredentialManager.class);
		when(user.credentialManager()).thenReturn(credentialManager);
		when(credentialManager.getStoredCredentialsByTypeStream(anyString()))
			.thenAnswer(i -> Stream.of(credential));
		when(user.getUsername()).thenReturn("resend-test-user");

		// Theme chain for the SMS text; simulation mode means no HTTP send.
		KeycloakContext keycloakContext = mock(KeycloakContext.class);
		when(session.getContext()).thenReturn(keycloakContext);
		when(keycloakContext.resolveLocale(user)).thenReturn(Locale.ENGLISH);
		ThemeManager themeManager = mock(ThemeManager.class);
		Theme theme = mock(Theme.class);
		when(session.theme()).thenReturn(themeManager);
		when(themeManager.getTheme(Theme.Type.LOGIN)).thenReturn(theme);
		Properties messages = new Properties();
		messages.setProperty("smsAuthText", "Code: %1$s valid %2$d min");
		when(theme.getEnhancedMessages(eq(realm), any(Locale.class))).thenReturn(messages);
		when(session.vault()).thenReturn(mock(VaultTranscriber.class));

		configMap = new HashMap<>();
		configMap.put("length", "6");
		configMap.put("ttl", "300");
		configMap.put("simulation", "true");
		configMap.put(SmsCodeSender.CONF_COOLDOWN, "60");
		configMap.put(SmsCodeSender.CONF_MAX_RESEND, "3");
		AuthenticatorConfigModel config = new AuthenticatorConfigModel();
		config.setConfig(configMap);
		when(context.getAuthenticatorConfig()).thenReturn(config);

		when(form.createForm(anyString())).thenReturn(mock(Response.class));
	}

	private void postResend() {
		MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
		params.add(SmsCodeSender.FORM_PARAM_RESEND, "1");
		params.add("code", "");
		when(request.getDecodedFormParameters()).thenReturn(params);
		authenticator.action(context);
	}

	@Test
	public void resendAfterCooldownRotatesCodeAndCounts() {
		notes.put(SmsCodeSender.NOTE_CODE, "111111");
		notes.put(SmsCodeSender.NOTE_LAST_SENT_AT, String.valueOf(System.currentTimeMillis() - 61_000));

		postResend();

		assertNotEquals("111111", notes.get(SmsCodeSender.NOTE_CODE), "old code must be replaced");
		assertNotNull(notes.get(SmsCodeSender.NOTE_TTL));
		assertEquals("1", notes.get(SmsCodeSender.NOTE_RESEND_COUNT));
		long lastSent = Long.parseLong(notes.get(SmsCodeSender.NOTE_LAST_SENT_AT));
		assertEquals(0, Math.max(0, System.currentTimeMillis() - lastSent) / 10_000, "send timestamp refreshed");
		verify(form).setInfo("smsAuthCodeResent");
		verify(context).challenge(any(Response.class));
		verify(session, never()).getProvider(org.keycloak.services.managers.BruteForceProtector.class);
	}

	@Test
	public void resendWithinCooldownIsRejectedWithoutSending() {
		notes.put(SmsCodeSender.NOTE_CODE, "111111");
		notes.put(SmsCodeSender.NOTE_LAST_SENT_AT, String.valueOf(System.currentTimeMillis() - 5_000));

		postResend();

		assertEquals("111111", notes.get(SmsCodeSender.NOTE_CODE), "code must not rotate inside the cooldown");
		assertNull(notes.get(SmsCodeSender.NOTE_RESEND_COUNT));
		verify(form).setError(eq("smsAuthResendTooSoon"), any());
		verify(context).challenge(any(Response.class));
		verify(session, never()).getProvider(org.keycloak.services.managers.BruteForceProtector.class);
	}

	@Test
	public void resendPastCeilingIsRejectedAndAudited() {
		notes.put(SmsCodeSender.NOTE_CODE, "111111");
		notes.put(SmsCodeSender.NOTE_LAST_SENT_AT, String.valueOf(System.currentTimeMillis() - 120_000));
		notes.put(SmsCodeSender.NOTE_RESEND_COUNT, "3");

		postResend();

		assertEquals("111111", notes.get(SmsCodeSender.NOTE_CODE));
		assertEquals("3", notes.get(SmsCodeSender.NOTE_RESEND_COUNT));
		verify(form).setError("smsAuthResendLimitReached");
		verify(event).error("sms_resend_limit_exceeded");
		verify(context).challenge(any(Response.class));
	}

	@Test
	public void resendDisabledWhenMaxCountZero() {
		configMap.put(SmsCodeSender.CONF_MAX_RESEND, "0");
		notes.put(SmsCodeSender.NOTE_CODE, "111111");
		notes.put(SmsCodeSender.NOTE_LAST_SENT_AT, String.valueOf(System.currentTimeMillis() - 120_000));

		postResend();

		assertEquals("111111", notes.get(SmsCodeSender.NOTE_CODE));
		verify(form).setError("smsAuthResendLimitReached");
		// The form the user gets back must hide the button: 0 remaining.
		verify(form).setAttribute(eq(SmsCodeSender.ATTR_RESEND_REMAINING), eq(0));
	}

	@Test
	public void resendParamWinsOverFilledCode() {
		notes.put(SmsCodeSender.NOTE_CODE, "111111");
		notes.put(SmsCodeSender.NOTE_LAST_SENT_AT, String.valueOf(System.currentTimeMillis() - 61_000));

		MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
		params.add(SmsCodeSender.FORM_PARAM_RESEND, "1");
		params.add("code", "111111");
		when(request.getDecodedFormParameters()).thenReturn(params);

		authenticator.action(context);

		verify(context, never()).success();
		assertNotEquals("111111", notes.get(SmsCodeSender.NOTE_CODE), "resend must rotate, not validate");
	}

	@Test
	public void normalValidationStillSucceeds() {
		notes.put(SmsCodeSender.NOTE_CODE, "123456");
		notes.put(SmsCodeSender.NOTE_TTL, String.valueOf(System.currentTimeMillis() + 60_000));

		MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
		params.add("code", "123456");
		when(request.getDecodedFormParameters()).thenReturn(params);

		authenticator.action(context);

		verify(context).success();
	}

	@Test
	public void authenticateRefreshWithinCooldownDoesNotSend() {
		notes.put(SmsCodeSender.NOTE_LAST_SENT_AT, String.valueOf(System.currentTimeMillis() - 5_000));

		authenticator.authenticate(context);

		assertNull(notes.get(SmsCodeSender.NOTE_CODE), "refresh inside the cooldown must not mint a code");
		verify(context).challenge(any(Response.class));
	}

	@Test
	public void authenticateRefreshAfterCooldownSendsAndCounts() {
		notes.put(SmsCodeSender.NOTE_LAST_SENT_AT, String.valueOf(System.currentTimeMillis() - 61_000));

		authenticator.authenticate(context);

		assertNotNull(notes.get(SmsCodeSender.NOTE_CODE), "refresh after the cooldown re-sends");
		assertEquals("1", notes.get(SmsCodeSender.NOTE_RESEND_COUNT), "refresh re-send counts toward the ceiling");
		verify(context).challenge(any(Response.class));
	}

	/**
	 * Points the gateway at a closed local port so the send genuinely throws, instead of the
	 * simulation lambda every other test here uses. Without a real failure path the throttle
	 * regression this guards against is invisible.
	 */
	private void useFailingGateway() {
		configMap.put("simulation", "false");
		configMap.put("apiurl", "https://127.0.0.1:1/sms");
		configMap.put("messageattribute", "message");
		configMap.put("receiverattribute", "to");
	}

	@Test
	public void failedResendStillBurnsCooldownAndAllowance() {
		useFailingGateway();
		notes.put(SmsCodeSender.NOTE_CODE, "111111");
		notes.put(SmsCodeSender.NOTE_LAST_SENT_AT, String.valueOf(System.currentTimeMillis() - 61_000));

		postResend();

		// The rate-limit clock and the resend counter must count attempts, not successes. If either
		// is only written on success, a failing-but-delivering gateway becomes an unbounded send loop.
		long lastSent = Long.parseLong(notes.get(SmsCodeSender.NOTE_LAST_SENT_AT));
		assertEquals(0, Math.max(0, System.currentTimeMillis() - lastSent) / 10_000,
			"a failed send must still start the cooldown");
		assertEquals("1", notes.get(SmsCodeSender.NOTE_RESEND_COUNT),
			"a failed send must still consume the resend allowance");
	}

	@Test
	public void failedSendLeavesNoUsableCode() {
		useFailingGateway();
		notes.put(SmsCodeSender.NOTE_CODE, "111111");
		notes.put(SmsCodeSender.NOTE_LAST_SENT_AT, String.valueOf(System.currentTimeMillis() - 61_000));

		postResend();

		// The prior code must not survive a failed send: the number now on file may never have
		// received it, which would let an earlier code authorise a newly entered destination.
		assertNull(notes.get(SmsCodeSender.NOTE_CODE),
			"a failed send must invalidate the previously issued code");
		assertNull(notes.get(SmsCodeSender.NOTE_TTL));
	}
}
