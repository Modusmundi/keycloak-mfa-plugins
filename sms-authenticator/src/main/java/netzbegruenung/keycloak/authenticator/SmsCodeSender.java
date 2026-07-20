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
	 * one-time password — to keep brute-force lockout working. Reporting a category outside the
	 * allow-list silently disables lockout for the SMS factor.
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
	 * Generates a fresh code and sends the SMS through the configured gateway, failing closed on both
	 * halves of the problem.
	 *
	 * <p>Before the send: any earlier code is invalidated and the send timestamp is recorded. The
	 * timestamp is the rate-limit clock, so it must count <em>attempts</em>, not successes — a gateway
	 * that accepts and then times out would otherwise leave no throttle state, and every retry would
	 * re-enter the unthrottled first-send path (unbounded outbound SMS, i.e. toll fraud). Clearing the
	 * code first means a failed send cannot leave a previously issued code usable for a number that
	 * never received one.
	 *
	 * <p>After the send: the code/ttl notes are written only once the gateway has accepted delivery,
	 * so a failure leaves no usable code and the caller shows the "SMS not sent" page rather than a
	 * code-entry form for an SMS that never went out.
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

		// Invalidate any earlier code and start the rate-limit clock before attempting the send, so a
		// failing gateway still throttles the retry and cannot leave a stale code live.
		long now = System.currentTimeMillis();
		authSession.removeAuthNote(NOTE_CODE);
		authSession.removeAuthNote(NOTE_TTL);
		authSession.setAuthNote(NOTE_LAST_SENT_AT, Long.toString(now));

		SmsServiceFactory.get(config, session).send(mobileNumber, smsText);

		// Only a delivered code becomes usable.
		authSession.setAuthNote(NOTE_CODE, code);
		authSession.setAuthNote(NOTE_TTL, Long.toString(now + (ttl * 1000L)));
	}

	/**
	 * Parses an integer config value (via {@link #intConfig}, which falls back to {@code fallback} when
	 * the value is absent, blank, non-numeric, or negative) and clamps the result into
	 * [{@code min}, {@code max}]. Guards against a misconfigured OTP length/TTL — e.g. a 1-digit code or
	 * a multi-day validity window — without breaking a working config.
	 */
	private static int boundedConfig(Map<String, String> config, String key, int min, int max, int fallback) {
		return Math.min(max, Math.max(min, intConfig(config, key, fallback)));
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
