package netzbegruenung.keycloak.enforce_mfa;

import org.junit.jupiter.api.Test;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * {@link RequiredActionEnrollment#isSatisfied} decides whether an offered MFA method counts as
 * "already set up". For a known, credential-mapped id it must do a real credential check; for an
 * unknown/stale/misconfigured id it must fail CLOSED (not satisfied) so the enforce step stays
 * enforced. Previously an unmapped id was reported satisfied for any fresh user, silently disabling
 * the whole step.
 */
public class RequiredActionEnrollmentTest {

	private static final String TOTP_ACTION = "CONFIGURE_TOTP"; // mapped to credential type "otp"
	private static final String UNKNOWN_ACTION = "ghost-action"; // not in the credential map

	private final KeycloakSession session = mock(KeycloakSession.class);
	private final RealmModel realm = mock(RealmModel.class);

	private UserModel userWithOtp(boolean configured) {
		UserModel user = mock(UserModel.class);
		SubjectCredentialManager scm = mock(SubjectCredentialManager.class);
		when(user.credentialManager()).thenReturn(scm);
		when(scm.isConfiguredFor("otp")).thenReturn(configured);
		return user;
	}

	@Test
	public void mappedActionUsesCredentialCheck() {
		assertTrue(RequiredActionEnrollment.isSatisfied(session, realm, userWithOtp(true), TOTP_ACTION));
		assertFalse(RequiredActionEnrollment.isSatisfied(session, realm, userWithOtp(false), TOTP_ACTION));
	}

	@Test
	public void unknownActionFailsClosed() {
		// A fresh user has no pending 'ghost-action' required action; this must NOT be read as satisfied.
		assertFalse(RequiredActionEnrollment.isSatisfied(session, realm, mock(UserModel.class), UNKNOWN_ACTION));
	}

	@Test
	public void needsEnrollmentStaysEnforcedForUnmappedOfferedId() {
		AuthenticatorConfigModel cfg = configWithOffered(UNKNOWN_ACTION);
		assertTrue(ConditionalEnforceMfaAuthenticator.needsEnrollment(session, realm, mock(UserModel.class), cfg),
			"an unmapped offered id must keep the MFA step enforced");
	}

	@Test
	public void needsEnrollmentSatisfiedWhenMappedCredentialPresent() {
		AuthenticatorConfigModel cfg = configWithOffered(TOTP_ACTION);
		assertFalse(ConditionalEnforceMfaAuthenticator.needsEnrollment(session, realm, userWithOtp(true), cfg));
		assertTrue(ConditionalEnforceMfaAuthenticator.needsEnrollment(session, realm, userWithOtp(false), cfg));
	}

	private static AuthenticatorConfigModel configWithOffered(String offered) {
		Map<String, String> map = new HashMap<>();
		map.put(EnforceMfaShared.CONFIG_OFFERED, offered);
		AuthenticatorConfigModel cfg = new AuthenticatorConfigModel();
		cfg.setConfig(map);
		return cfg;
	}
}
