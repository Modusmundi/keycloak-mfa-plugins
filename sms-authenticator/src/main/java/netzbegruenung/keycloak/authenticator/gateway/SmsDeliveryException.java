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

package netzbegruenung.keycloak.authenticator.gateway;

/**
 * Thrown when the SMS gateway does not accept a message — a non-2xx HTTP status, a connect/read
 * timeout, or a transport error. It exists so a failed send fails <em>closed</em>: the caller's
 * {@code catch} turns it into the generic "SMS not sent" page instead of presenting a code-entry
 * form for a code that never reached the user. Unchecked so it can propagate through the
 * {@link SmsService#send} contract (which declares no checked exceptions) without swallowing.
 *
 * <p>The message deliberately carries only the HTTP status / failure kind — never the OTP, phone
 * number, gateway URL, or credentials.
 */
public class SmsDeliveryException extends RuntimeException {

	public SmsDeliveryException(String message) {
		super(message);
	}

	public SmsDeliveryException(String message, Throwable cause) {
		super(message, cause);
	}
}
