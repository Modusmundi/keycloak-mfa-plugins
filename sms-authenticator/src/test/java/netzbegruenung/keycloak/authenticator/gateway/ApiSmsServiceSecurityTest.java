/*
 * Copyright 2026 Frank Winston Crum
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 */

package netzbegruenung.keycloak.authenticator.gateway;

import org.junit.jupiter.api.Test;

import java.net.http.HttpRequest;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A5 — Force HTTPS on API URLs. The scheme predicate accepts HTTPS (and http only to loopback for
 * dev); when the toggle is on a non-HTTPS gateway URL aborts the send before any request is made.
 */
public class ApiSmsServiceSecurityTest {

	@Test
	public void httpsUrlIsAllowed() {
		assertTrue(ApiSmsService.isApiUrlSecure("https://api.twilio.com/2010-04-01/Messages.json"));
	}

	@Test
	public void schemeIsCaseInsensitive() {
		assertTrue(ApiSmsService.isApiUrlSecure("HTTPS://API.TWILIO.COM/send"));
	}

	@Test
	public void httpToLoopbackIsAllowedForDev() {
		assertTrue(ApiSmsService.isApiUrlSecure("http://localhost:8080/sms"));
		assertTrue(ApiSmsService.isApiUrlSecure("http://127.0.0.1/sms"));
	}

	@Test
	public void plainHttpToRemoteHostIsRejected() {
		assertFalse(ApiSmsService.isApiUrlSecure("http://sms.example.com/send"));
	}

	@Test
	public void nonHttpSchemesAreRejected() {
		assertFalse(ApiSmsService.isApiUrlSecure("ftp://sms.example.com/send"));
		assertFalse(ApiSmsService.isApiUrlSecure("example.com/send"));
	}

	@Test
	public void nullBlankOrUnparseableIsRejected() {
		assertFalse(ApiSmsService.isApiUrlSecure(null));
		assertFalse(ApiSmsService.isApiUrlSecure(""));
		assertFalse(ApiSmsService.isApiUrlSecure("  "));
		assertFalse(ApiSmsService.isApiUrlSecure("http://exa mple.com"));
	}

	@Test
	public void sendOverPlainHttpIsRefusedWhenForceOn() {
		// Default (no key) is force-on; the send must abort before touching the network.
		Map<String, String> config = baseConfig();
		config.put("apiurl", "http://sms.example.com/send");
		SmsService svc = SmsServiceFactory.get(config);
		assertThrows(IllegalStateException.class, () -> svc.send("+15555550100", "code 123456"));
	}

	@Test
	public void sendOverPlainHttpIsPermittedWhenForceOff() {
		// Explicitly disabled: the scheme check must not reject. A loopback port that refuses the
		// connection keeps this hermetic — the send now fails closed with SmsDeliveryException (a
		// delivery failure), NOT IllegalStateException, proving the scheme check passed.
		Map<String, String> config = baseConfig();
		config.put("forceHttpsApiUrl", "false");
		config.put("apiurl", "http://127.0.0.1:1/send");
		SmsService svc = SmsServiceFactory.get(config);
		assertThrows(SmsDeliveryException.class, () -> svc.send("+15555550100", "code 123456"));
	}

	// F2 — every outbound request must carry a timeout so a hung gateway cannot pin the auth thread.

	@Test
	public void jsonRequestCarriesTimeout() {
		HttpRequest req = new ApiSmsService(timeoutConfig()).jsonRequest("{}").build();
		assertTrue(req.timeout().isPresent(), "JSON POST request must set a timeout");
		assertEquals(ApiSmsService.REQUEST_TIMEOUT, req.timeout().get());
	}

	@Test
	public void urlencodedRequestCarriesTimeout() {
		HttpRequest req = new ApiSmsService(timeoutConfig()).urlencodedRequest("+15555550100", "code 123456").build();
		assertTrue(req.timeout().isPresent(), "urlencoded POST request must set a timeout");
		assertEquals(ApiSmsService.REQUEST_TIMEOUT, req.timeout().get());
	}

	@Test
	public void getRequestCarriesTimeout() {
		Map<String, String> config = timeoutConfig();
		config.put("getUrl", "/send?to={phone}&msg={message}");
		HttpRequest req = new ApiSmsService(config).getRequest("+15555550100", "code 123456").build();
		assertTrue(req.timeout().isPresent(), "GET request must set a timeout");
		assertEquals(ApiSmsService.REQUEST_TIMEOUT, req.timeout().get());
	}

	private static Map<String, String> timeoutConfig() {
		Map<String, String> config = baseConfig();
		config.put("apiurl", "https://api.example.com/send");
		return config;
	}

	private static Map<String, String> baseConfig() {
		Map<String, String> config = new HashMap<>();
		config.put("simulation", "false");
		config.put("senderId", "Keycloak");
		config.put("messageattribute", "text");
		config.put("receiverattribute", "to");
		config.put("senderattribute", "from");
		config.put("countrycode", "+1");
		return config;
	}
}
