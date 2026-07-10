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

import com.google.i18n.phonenumbers.PhoneNumberUtil;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * F1 — the {@code allowedRegions} / {@code numberTypeFilters} allowlist is a security control
 * (anti-toll-fraud) and must be enforced fail-closed at enrolment whenever it is configured,
 * independent of the {@code normalizePhoneNumber} / {@code forceRetryOnBadFormat} formatting
 * toggles. Before the fix the allowlist silently no-opped unless BOTH toggles were on, so a
 * user could enrol a disallowed (e.g. out-of-region / premium-rate) number and have Keycloak
 * text it. These tests drive {@link PhoneNumberRequiredAction#processAction} across the flag
 * matrix and assert an out-of-region number is rejected in every case.
 *
 * <p>Numbers are taken from libphonenumber's own example set so {@code isValidNumber} passes
 * deterministically.
 */
public class PhoneNumberRegionEnforcementTest {

	private static final PhoneNumberUtil PHONE_UTIL = PhoneNumberUtil.getInstance();
	private static final String US_NUMBER = e164("US");
	private static final String GB_NUMBER = e164("GB");

	private PhoneNumberRequiredAction requiredAction;
	private RequiredActionContext context;
	private AuthenticationSessionModel authSession;
	private HttpRequest request;
	private LoginFormsProvider form;
	private RealmModel realm;
	private KeycloakSession session;
	private UserModel user;
	private Map<String, String> configMap;
	private Map<String, String> notes;

	private static String e164(String region) {
		return PHONE_UTIL.format(PHONE_UTIL.getExampleNumber(region), PhoneNumberUtil.PhoneNumberFormat.E164);
	}

	@BeforeEach
	public void setup() {
		requiredAction = new PhoneNumberRequiredAction();
		context = mock(RequiredActionContext.class);
		authSession = mock(AuthenticationSessionModel.class);
		request = mock(HttpRequest.class);
		form = mock(LoginFormsProvider.class, org.mockito.Mockito.RETURNS_SELF);
		realm = mock(RealmModel.class);
		session = mock(KeycloakSession.class);
		user = mock(UserModel.class);

		when(context.getAuthenticationSession()).thenReturn(authSession);
		when(context.getHttpRequest()).thenReturn(request);
		when(context.form()).thenReturn(form);
		when(context.getRealm()).thenReturn(realm);
		when(context.getSession()).thenReturn(session);
		when(context.getUser()).thenReturn(user);
		when(user.getUsername()).thenReturn("enroll-test-user");

		notes = new HashMap<>();
		doAnswer(i -> notes.put(i.getArgument(0), i.getArgument(1)))
			.when(authSession).setAuthNote(anyString(), anyString());
		when(authSession.getAuthNote(anyString())).thenAnswer(i -> notes.get(i.getArgument(0)));

		// getCountryCodeList (reached on the re-prompt path) needs a locale-resolving context.
		KeycloakContext keycloakContext = mock(KeycloakContext.class);
		when(session.getContext()).thenReturn(keycloakContext);
		when(keycloakContext.resolveLocale(user)).thenReturn(Locale.ENGLISH);

		configMap = new HashMap<>();
		configMap.put("countrycode", "+1");
		AuthenticatorConfigModel config = new AuthenticatorConfigModel();
		config.setConfig(configMap);
		when(realm.getAuthenticatorConfigByAlias("sms-2fa")).thenReturn(config);

		when(form.createForm(anyString())).thenReturn(mock(Response.class));
	}

	private void enroll(String mobileNumber) {
		MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
		params.add("mobile_number", mobileNumber);
		when(request.getDecodedFormParameters()).thenReturn(params);
		requiredAction.processAction(context);
	}

	private void assertRejected() {
		verify(context, never()).success();
		verify(context).challenge(any(Response.class));
		verify(authSession, never()).addRequiredAction(PhoneValidationRequiredAction.PROVIDER_ID);
	}

	private void assertAccepted() {
		verify(context).success();
		verify(authSession).addRequiredAction(PhoneValidationRequiredAction.PROVIDER_ID);
		verify(context, never()).challenge(any(Response.class));
	}

	// --- The three flag combinations: an out-of-region number must be rejected in all of them ---

	@Test
	public void outOfRegionRejected_normalizeFalse_forceRetryFalse() {
		// The default configuration — previously the allowlist did nothing here (the bug).
		configMap.put("allowedRegions", "US");
		configMap.put("normalizePhoneNumber", "false");
		configMap.put("forceRetryOnBadFormat", "false");
		enroll(GB_NUMBER);
		assertRejected();
		verify(form).setError("numberFormatRegionNotAllowed");
	}

	@Test
	public void outOfRegionRejected_normalizeTrue_forceRetryFalse() {
		// The trap case — the region check ran and logged, but the SMS still went out (the bug).
		configMap.put("allowedRegions", "US");
		configMap.put("normalizePhoneNumber", "true");
		configMap.put("forceRetryOnBadFormat", "false");
		enroll(GB_NUMBER);
		assertRejected();
		verify(form).setError("numberFormatRegionNotAllowed");
	}

	@Test
	public void outOfRegionRejected_normalizeTrue_forceRetryTrue() {
		// The only previously-safe configuration — must still reject (regression guard).
		configMap.put("allowedRegions", "US");
		configMap.put("normalizePhoneNumber", "true");
		configMap.put("forceRetryOnBadFormat", "true");
		enroll(GB_NUMBER);
		assertRejected();
	}

	// --- An in-region number is accepted regardless of the formatting toggles ---

	@Test
	public void inRegionAccepted_normalizeFalse_forceRetryFalse() {
		configMap.put("allowedRegions", "US");
		enroll(US_NUMBER);
		assertAccepted();
	}

	@Test
	public void inRegionAccepted_normalizeTrue_forceRetryTrue() {
		configMap.put("allowedRegions", "US");
		configMap.put("normalizePhoneNumber", "true");
		configMap.put("forceRetryOnBadFormat", "true");
		enroll(US_NUMBER);
		assertAccepted();
	}

	// --- Fail-closed on an unvalidatable number when an allowlist is configured ---

	@Test
	public void unparseableRejectedWhenAllowlistConfigured() {
		configMap.put("allowedRegions", "US");
		enroll("12"); // not a valid number in any region
		assertRejected();
	}

	// --- numberTypeFilters also gate independently of the formatting toggles ---

	@Test
	public void numberTypeFilterEnforcedWithoutFormattingToggles() {
		// GB example number is FIXED_LINE_OR_MOBILE; restricting to VOIP must reject it.
		configMap.put("numberTypeFilters", "VOIP");
		enroll(GB_NUMBER);
		assertRejected();
	}

	// --- Backward compatibility: no allowlist => no gate, any region enrols ---

	@Test
	public void noAllowlistAllowsAnyRegion() {
		enroll(GB_NUMBER); // no allowedRegions / numberTypeFilters set
		assertAccepted();
	}

	// --- F3: a missing mobile_number form field re-prompts instead of throwing ---

	@Test
	public void missingMobileNumberParamRepromptsWithoutNpe() {
		MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
		// no "mobile_number" key
		when(request.getDecodedFormParameters()).thenReturn(params);
		assertDoesNotThrow(() -> requiredAction.processAction(context));
		verify(context, never()).success();
		verify(context).challenge(any(Response.class));
	}
}
