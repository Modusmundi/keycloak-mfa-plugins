package netzbegruenung.keycloak.enforce_mfa;

import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.Constants;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RequiredActionProviderModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Enforcement-bypass regression tests for {@link ConditionalEnforceMfaAuthenticator#action}. The
 * screen only offers ENABLED, installed required actions, but a forged POST can submit any string.
 * {@code action()} must accept only methods in the enabled+installed resolved set — never a
 * configured-but-disabled/uninstalled or arbitrary id — otherwise the step would complete
 * ({@code context.success()}) while the chosen required action is silently dropped and no MFA is
 * ever enrolled.
 */
public class ConditionalEnforceMfaAuthenticatorTest {

	private static final String ENABLED_ID = "CONFIGURE_TOTP";
	private static final String DISABLED_ID = "webauthn-register";
	private static final String STALE_ID = "email-authenticator-setup"; // configured but not installed in realm

	private ConditionalEnforceMfaAuthenticator authenticator;
	private AuthenticationFlowContext context;
	private HttpRequest httpRequest;
	private RealmModel realm;
	private AuthenticationSessionModel authSession;
	private LoginFormsProvider form;

	@BeforeEach
	public void setup() {
		authenticator = new ConditionalEnforceMfaAuthenticator();
		context = mock(AuthenticationFlowContext.class);
		httpRequest = mock(HttpRequest.class);
		realm = mock(RealmModel.class);
		authSession = mock(AuthenticationSessionModel.class);
		form = mock(LoginFormsProvider.class);

		// Offered config lists an enabled, a disabled, and a stale (uninstalled) required action.
		Map<String, String> cfg = new HashMap<>();
		cfg.put(EnforceMfaShared.CONFIG_OFFERED,
			String.join(Constants.CFG_DELIMITER, ENABLED_ID, DISABLED_ID, STALE_ID));
		AuthenticatorConfigModel authCfg = new AuthenticatorConfigModel();
		authCfg.setConfig(cfg);

		when(context.getHttpRequest()).thenReturn(httpRequest);
		when(context.getAuthenticatorConfig()).thenReturn(authCfg);
		when(context.getRealm()).thenReturn(realm);
		when(context.getAuthenticationSession()).thenReturn(authSession);
		when(context.form()).thenReturn(form);
		when(form.createErrorPage(any())).thenReturn(mock(Response.class));
		when(authSession.getRequiredActions()).thenReturn(Collections.emptySet());
		when(realm.getName()).thenReturn("test-realm");

		when(realm.getRequiredActionProviderById(ENABLED_ID)).thenReturn(requiredAction(ENABLED_ID, true));
		when(realm.getRequiredActionProviderById(DISABLED_ID)).thenReturn(requiredAction(DISABLED_ID, false));
		// STALE_ID resolves to nothing (not installed) via either lookup.
		when(realm.getRequiredActionProviderById(STALE_ID)).thenReturn(null);
		when(realm.getRequiredActionProviderByAlias(STALE_ID)).thenReturn(null);
	}

	private static RequiredActionProviderModel requiredAction(String id, boolean enabled) {
		RequiredActionProviderModel m = new RequiredActionProviderModel();
		m.setProviderId(id);
		m.setAlias(id);
		m.setEnabled(enabled);
		return m;
	}

	private void submit(String mfaMethod) {
		MultivaluedMap<String, String> params = new MultivaluedHashMap<>();
		if (mfaMethod != null) {
			params.add(ConditionalEnforceMfaAuthenticator.FORM_PARAM_MFA_METHOD, mfaMethod);
		}
		when(httpRequest.getDecodedFormParameters()).thenReturn(params);
		authenticator.action(context);
	}

	private void assertRejected() {
		verify(context, never()).success();
		verify(authSession, never()).addRequiredAction(anyString());
		verify(context).failure(AuthenticationFlowError.CREDENTIAL_SETUP_REQUIRED);
	}

	@Test
	public void acceptsEnabledOfferedMethod() {
		submit(ENABLED_ID);
		verify(authSession).addRequiredAction(ENABLED_ID);
		verify(context).success();
		verify(context, never()).failure(any(AuthenticationFlowError.class));
	}

	@Test
	public void rejectsForgedDisabledMethod() {
		// The disabled action is never shown, but a crafted POST submits it directly.
		submit(DISABLED_ID);
		assertRejected();
	}

	@Test
	public void rejectsForgedStaleUninstalledMethod() {
		submit(STALE_ID);
		assertRejected();
	}

	@Test
	public void rejectsArbitraryUnknownMethod() {
		submit("totally-made-up-action");
		assertRejected();
	}
}
