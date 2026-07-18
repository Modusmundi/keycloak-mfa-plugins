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

import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;

import org.junit.jupiter.api.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.Mockito.mock;

/**
 * The mobile-number credential is a destination, not a verifiable secret. {@code isValid} must fail
 * closed so that presenting the (guessable) phone number as the credential value never authenticates
 * — otherwise a generic {@code CredentialInputValidator} path (e.g. direct grant) could be satisfied
 * with public information. OTP verification is done elsewhere against the transient auth-note code.
 */
public class SmsAuthCredentialProviderTest {

	@Test
	public void isValidFailsClosedForPhoneNumberInput() {
		KeycloakSession session = mock(KeycloakSession.class);
		SmsAuthCredentialProvider provider = new SmsAuthCredentialProvider(session);

		RealmModel realm = mock(RealmModel.class);
		UserModel user = mock(UserModel.class);
		// The stored phone number supplied as the challenge response must NOT validate.
		UserCredentialModel input = new UserCredentialModel("cred-id", SmsAuthCredentialModel.TYPE, "+15555550100");

		assertFalse(provider.isValid(realm, user, input),
			"isValid must never accept the stored phone number as a credential value");
	}
}
