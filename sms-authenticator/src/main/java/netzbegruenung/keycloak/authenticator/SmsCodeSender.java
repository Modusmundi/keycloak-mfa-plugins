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
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 */

package netzbegruenung.keycloak.authenticator;

import netzbegruenung.keycloak.authenticator.gateway.SmsServiceFactory;

import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;

/**
 * Shared code-send logic and per-auth-session send throttling for the SMS login
 * challenge (SmsAuthenticator) and the enrollment validation step
 * (PhoneValidationRequiredAction).
 *
 * Rate limiting is business-configurable via the shared "sms-2fa" authenticator
 * config (see SmsAuthenticatorFactory): {@code resendCooldownSeconds} is the
 * minimum interval between sends within one authentication session and
 * {@code resendMaxCount} caps how many additional codes (after the first) may be
 * sent per session. Both are enforced server-side at every send site, so page
 * refreshes cannot be used to spam SMS sends either.
 */
final class SmsCodeSender {

	static final String NOTE_CODE = "code";
	static final String NOTE_TTL = "ttl";
	/** Epoch millis of the most recent SMS send in this auth session (set on every send, including the first). */
	static final String NOTE_LAST_SENT_AT = "smsLastSentAt";
	/** Number of sends after the first in this auth session (explicit resends and refresh-triggered re-sends). */
	static final String NOTE_RESEND_COUNT = "smsResendCount";

	static final String CONF_COOLDOWN = "resendCooldownSeconds";
	static final String CONF_MAX_RESEND = "resendMaxCount";
	static final int DEFAULT_COOLDOWN_SECONDS = 60;
	static final int DEFAULT_MAX_RESEND = 3;

	/** Form parameter posted by the template's resend button. */
	static final String FORM_PARAM_RESEND = "resend";
	/** Template attribute: how many resends the user has left (0 hides the button). */
	static final String ATTR_RESEND_REMAINING = "smsResendRemaining";
	/** Template attribute: seconds until the next resend is permitted (cosmetic countdown; server enforces). */
	static final String ATTR_RESEND_WAIT = "smsResendWaitSeconds";

	private SmsCodeSender() {
	}

	/**
	 * Generates a fresh code, overwrites the code/ttl auth notes (invalidating any earlier code),
	 * records the send timestamp, and sends the SMS through the configured gateway.
	 */
	static void sendCode(KeycloakSession session, RealmModel realm, UserModel user,
			AuthenticationSessionModel authSession, Map<String, String> config,
			String mobileNumber) throws IOException {
		int length = Integer.parseInt(config.get("length"));
		int ttl = Integer.parseInt(config.get("ttl"));

		String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
		authSession.setAuthNote(NOTE_CODE, code);
		authSession.setAuthNote(NOTE_TTL, Long.toString(System.currentTimeMillis() + (ttl * 1000L)));
		authSession.setAuthNote(NOTE_LAST_SENT_AT, Long.toString(System.currentTimeMillis()));

		Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
		Locale locale = session.getContext().resolveLocale(user);
		String smsAuthText = theme.getEnhancedMessages(realm, locale).getProperty("smsAuthText");
		String smsText = String.format(smsAuthText, code, Math.floorDiv(ttl, 60));

		SmsServiceFactory.get(config, session).send(mobileNumber, smsText);
	}

	/** Minimum seconds between sends in one auth session; 0 disables the cooldown. */
	static int cooldownSeconds(Map<String, String> config) {
		return intConfig(config, CONF_COOLDOWN, DEFAULT_COOLDOWN_SECONDS);
	}

	/** Max additional codes (after the first) per auth session; 0 disables resending entirely. */
	static int maxResendCount(Map<String, String> config) {
		return intConfig(config, CONF_MAX_RESEND, DEFAULT_MAX_RESEND);
	}

	/** Sends after the first that have already happened in this auth session. */
	static int resendsUsed(AuthenticationSessionModel authSession) {
		String count = authSession.getAuthNote(NOTE_RESEND_COUNT);
		if (count == null) {
			return 0;
		}
		try {
			return Integer.parseInt(count);
		} catch (NumberFormatException e) {
			return 0;
		}
	}

	/** Seconds until the cooldown allows another send; 0 when no send happened yet or the cooldown elapsed. */
	static long secondsUntilResendAllowed(AuthenticationSessionModel authSession, int cooldownSeconds) {
		String lastSentAt = authSession.getAuthNote(NOTE_LAST_SENT_AT);
		if (lastSentAt == null || cooldownSeconds <= 0) {
			return 0;
		}
		long allowedAt;
		try {
			allowedAt = Long.parseLong(lastSentAt) + (cooldownSeconds * 1000L);
		} catch (NumberFormatException e) {
			return 0;
		}
		long remainingMillis = allowedAt - System.currentTimeMillis();
		return remainingMillis <= 0 ? 0 : (remainingMillis + 999) / 1000;
	}

	private static int intConfig(Map<String, String> config, String key, int defaultValue) {
		if (config == null) {
			return defaultValue;
		}
		String value = config.get(key);
		if (value == null || value.isBlank()) {
			return defaultValue;
		}
		try {
			int parsed = Integer.parseInt(value.trim());
			return parsed < 0 ? defaultValue : parsed;
		} catch (NumberFormatException e) {
			return defaultValue;
		}
	}
}
