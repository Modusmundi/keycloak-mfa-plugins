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

import org.jboss.logging.Logger;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.theme.Theme;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

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

	private static final Logger logger = Logger.getLogger(SmsCodeSender.class);

	/** Bounds for the generated OTP so a misconfigured 'length'/'ttl' cannot yield a trivially weak code. */
	static final int MIN_CODE_LENGTH = 6;
	static final int MAX_CODE_LENGTH = 12;
	static final int DEFAULT_CODE_LENGTH = 6;
	static final int MIN_TTL_SECONDS = 30;
	static final int MAX_TTL_SECONDS = 3600;
	static final int DEFAULT_TTL_SECONDS = 300;

	static final String NOTE_CODE = "code";
	static final String NOTE_TTL = "ttl";
	/** Epoch millis of the most recent SMS send in this auth session (set on every send, including the first). */
	static final String NOTE_LAST_SENT_AT = "smsLastSentAt";
	/** Number of sends after the first in this auth session (explicit resends and refresh-triggered re-sends). */
	static final String NOTE_RESEND_COUNT = "smsResendCount";

	/**
	 * Authentication categories reported to the brute-force protector for a failed SMS code. Keycloak
	 * (>= 26.7) only counts a failed login toward lockout when its category is in an allow-list
	 * (password, otp, recovery-authn-codes). The SMS authenticator's own reference category
	 * ("mobile-number") is not on that list, so a failed SMS code is reported as "otp" — it is a
	 * one-time password — to keep brute-force lockout working. Passing an empty/other category (or the
	 * pre-26.7 {@code null}) would silently disable lockout for the SMS factor.
	 */
	static final Set<String> BRUTE_FORCE_CATEGORIES = Set.of("otp");

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
	 * Generates a fresh code and sends the SMS through the configured gateway, then — only once the
	 * gateway has accepted delivery — overwrites the code/ttl auth notes (invalidating any earlier
	 * code) and records the send timestamp. Persisting the challenge state <em>after</em> the send
	 * means a delivery failure (which the gateway surfaces as an exception) fails closed: no usable
	 * code note is stored and the caller shows the "SMS not sent" page rather than a code-entry form
	 * for an SMS that never went out.
	 */
	static void sendCode(KeycloakSession session, RealmModel realm, UserModel user,
			AuthenticationSessionModel authSession, Map<String, String> config,
			String mobileNumber) throws IOException {
		int length = boundedConfig(config, "length", MIN_CODE_LENGTH, MAX_CODE_LENGTH, DEFAULT_CODE_LENGTH);
		int ttl = boundedConfig(config, "ttl", MIN_TTL_SECONDS, MAX_TTL_SECONDS, DEFAULT_TTL_SECONDS);

		String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);

		Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
		Locale locale = session.getContext().resolveLocale(user);
		String smsAuthText = theme.getEnhancedMessages(realm, locale).getProperty("smsAuthText");
		String smsText = String.format(smsAuthText, code, Math.floorDiv(ttl, 60));

		// Send first — a failure here throws and no challenge state is persisted (fail closed).
		SmsServiceFactory.get(config, session).send(mobileNumber, smsText);

		long now = System.currentTimeMillis();
		authSession.setAuthNote(NOTE_CODE, code);
		authSession.setAuthNote(NOTE_TTL, Long.toString(now + (ttl * 1000L)));
		authSession.setAuthNote(NOTE_LAST_SENT_AT, Long.toString(now));
	}

	/**
	 * Parses an integer config value and clamps it into [{@code min}, {@code max}], falling back to
	 * {@code fallback} when absent or non-numeric. Guards against a misconfigured OTP length/TTL —
	 * e.g. a 1-digit code or a multi-day validity window — without breaking a working config.
	 */
	private static int boundedConfig(Map<String, String> config, String key, int min, int max, int fallback) {
		String raw = config == null ? null : config.get(key);
		int value;
		try {
			value = Integer.parseInt(raw.trim());
		} catch (NumberFormatException | NullPointerException e) {
			logger.warnf("SMS OTP config '%s' is missing or not a number; using default %d", key, fallback);
			return fallback;
		}
		if (value < min) {
			logger.warnf("SMS OTP config '%s'=%d is below the minimum %d; clamping to %d", key, value, min, min);
			return min;
		}
		if (value > max) {
			logger.warnf("SMS OTP config '%s'=%d is above the maximum %d; clamping to %d", key, value, max, max);
			return max;
		}
		return value;
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
