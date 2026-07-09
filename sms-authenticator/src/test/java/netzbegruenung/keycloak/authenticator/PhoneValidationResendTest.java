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
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Resend + rate-limit behavior of the enrollment (phone validation) step — mirrors the
 * login-path cases in SmsAuthenticatorResendTest.
 */
public class PhoneValidationResendTest {

	private PhoneValidationRequiredAction requiredAction;
	private RequiredActionContext context;
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
		requiredAction = new PhoneValidationRequiredAction();
		context = mock(RequiredActionContext.class);
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
		when(user.getUsername()).thenReturn("enroll-test-user");
		when(realm.isBruteForceProtected()).thenReturn(false);

		notes = new HashMap<>();
		doAnswer(i -> notes.put(i.getArgument(0), i.getArgument(1)))
			.when(authSession).setAuthNote(anyString(), anyString());
		when(authSession.getAuthNote(anyString())).thenAnswer(i -> notes.get(i.getArgument(0)));
		notes.put("mobile_number", "+15555550100");

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
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(config);

		when(form.createForm(anyString())).thenReturn(mock(Response.class));
	}

	private void postResend() {
		MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
		params.add(SmsCodeSender.FORM_PARAM_RESEND, "1");
		params.add("code", "");
		when(request.getDecodedFormParameters()).thenReturn(params);
		requiredAction.processAction(context);
	}

	@Test
	public void resendAfterCooldownRotatesCodeAndCounts() {
		notes.put(SmsCodeSender.NOTE_CODE, "111111");
		notes.put(SmsCodeSender.NOTE_LAST_SENT_AT, String.valueOf(System.currentTimeMillis() - 61_000));

		postResend();

		assertNotEquals("111111", notes.get(SmsCodeSender.NOTE_CODE), "old code must be replaced");
		assertEquals("1", notes.get(SmsCodeSender.NOTE_RESEND_COUNT));
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
	}

	@Test
	public void resendPastCeilingIsRejectedAndAudited() {
		notes.put(SmsCodeSender.NOTE_CODE, "111111");
		notes.put(SmsCodeSender.NOTE_LAST_SENT_AT, String.valueOf(System.currentTimeMillis() - 120_000));
		notes.put(SmsCodeSender.NOTE_RESEND_COUNT, "3");

		postResend();

		assertEquals("111111", notes.get(SmsCodeSender.NOTE_CODE));
		verify(form).setError("smsAuthResendLimitReached");
		verify(event).error("sms_resend_limit_exceeded");
		verify(context).challenge(any(Response.class));
	}
}
