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

/**
 * Renders phone numbers for server logs. When masking is enabled the number is
 * reduced to its last four digits (e.g. {@code ••••••1234}); when disabled the raw
 * number is returned unchanged. Controlled per authenticator config by the
 * {@code maskPhoneNumberInLogs} flag (default on), the same way {@code hideResponsePayload}
 * gates response-body logging.
 */
public final class PhoneNumberLogMasker {

	static final String MASK_PREFIX = "••••••";

	private PhoneNumberLogMasker() {
	}

	/**
	 * @param phoneNumber the raw phone number (may be null)
	 * @param mask        when true, return last-4 only; when false, return the raw value
	 * @return the value to place in a log statement
	 */
	public static String forLog(String phoneNumber, boolean mask) {
		if (!mask || phoneNumber == null) {
			return phoneNumber;
		}
		String digits = phoneNumber.replaceAll("\\D", "");
		if (digits.length() < 4) {
			// Too short to reveal a meaningful suffix without exposing the whole number.
			return MASK_PREFIX;
		}
		return MASK_PREFIX + digits.substring(digits.length() - 4);
	}
}
