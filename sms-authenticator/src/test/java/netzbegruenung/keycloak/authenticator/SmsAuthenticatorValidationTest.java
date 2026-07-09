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
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.events.EventBuilder;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Validation branches of the login SMS challenge that the resend suite does not cover: a wrong
 * code (the constant-time comparison's false branch) and a correct-but-expired code (TTL rejection).
 * Brute-force protection is off, so these exercise the plain validation logic in isolation.
 */
public class SmsAuthenticatorValidationTest {

	private SmsAuthenticator authenticator;
	private AuthenticationFlowContext context;
	private AuthenticationSessionModel authSession;
	private HttpRequest request;
	private LoginFormsProvider form;
	private RealmModel realm;
	private UserModel user;
	private EventBuilder event;
	private Map<String, String> configMap;
	private Map<String, String> notes;

	@BeforeEach
	public void setup() {
		authenticator = new SmsAuthenticator();
		context = mock(AuthenticationFlowContext.class);
		authSession = mock(AuthenticationSessionModel.class);
		request = mock(HttpRequest.class);
		form = mock(LoginFormsProvider.class, org.mockito.Mockito.RETURNS_SELF);
		realm = mock(RealmModel.class);
		user = mock(UserModel.class);
		event = mock(EventBuilder.class);

		when(context.getAuthenticationSession()).thenReturn(authSession);
		when(context.getHttpRequest()).thenReturn(request);
		when(context.form()).thenReturn(form);
		when(context.getRealm()).thenReturn(realm);
		when(context.getUser()).thenReturn(user);
		when(context.getEvent()).thenReturn(event);
		when(event.user(any(UserModel.class))).thenReturn(event);

		// Brute-force off: the validation branches must stand on their own.
		when(realm.isBruteForceProtected()).thenReturn(false);
		when(user.getUsername()).thenReturn("validation-test-user");

		notes = new HashMap<>();
		doAnswer(i -> notes.put(i.getArgument(0), i.getArgument(1)))
			.when(authSession).setAuthNote(anyString(), anyString());
		when(authSession.getAuthNote(anyString())).thenAnswer(i -> notes.get(i.getArgument(0)));

		configMap = new HashMap<>();
		configMap.put("length", "6");
		configMap.put("ttl", "300");
		configMap.put("simulation", "true");
		AuthenticatorConfigModel config = new AuthenticatorConfigModel();
		config.setConfig(configMap);
		when(context.getAuthenticatorConfig()).thenReturn(config);

		when(form.createForm(anyString())).thenReturn(mock(Response.class));
		when(form.createErrorPage(any(Response.Status.class))).thenReturn(mock(Response.class));
	}

	private void submitCode(String code) {
		MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
		params.add("code", code);
		when(request.getDecodedFormParameters()).thenReturn(params);
		authenticator.action(context);
	}

	@Test
	public void wrongCodeIsRejectedAsInvalidCredentials() {
		notes.put(SmsCodeSender.NOTE_CODE, "123456");
		notes.put(SmsCodeSender.NOTE_TTL, String.valueOf(System.currentTimeMillis() + 60_000));

		submitCode("000000");

		verify(context, never()).success();
		verify(form).setError("smsAuthCodeInvalid");
		verify(context).failureChallenge(eq(AuthenticationFlowError.INVALID_CREDENTIALS), any(Response.class));
	}

	@Test
	public void correctButExpiredCodeIsRejectedAsExpired() {
		notes.put(SmsCodeSender.NOTE_CODE, "123456");
		notes.put(SmsCodeSender.NOTE_TTL, String.valueOf(System.currentTimeMillis() - 1_000));

		submitCode("123456");

		verify(context, never()).success();
		verify(form).setError("smsAuthCodeExpired");
		verify(context).failureChallenge(eq(AuthenticationFlowError.EXPIRED_CODE), any(Response.class));
	}
}
