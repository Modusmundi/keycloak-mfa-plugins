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

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Delivery fail-closed + log redaction for the active SMS gateway. A hermetic loopback HTTP server
 * stands in for the SMS gateway so these are real end-to-end sends without touching the network.
 */
public class ApiSmsServiceDeliveryTest {

	private static final String OTP = "654321";
	private static final String OTP_MESSAGE = "Your login code is " + OTP;
	private static final String PHONE = "+15555550100";
	private static final String TOKEN = "s3cr3t-gateway-token";

	private HttpServer server;
	private volatile int responseStatus = 200;
	private volatile String responseBody = "{\"ok\":true}";

	@BeforeEach
	void startServer() throws IOException {
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/send", this::handle);
		server.start();
	}

	@AfterEach
	void stopServer() {
		if (server != null) {
			server.stop(0);
		}
	}

	private void handle(HttpExchange exchange) throws IOException {
		exchange.getRequestBody().readAllBytes();
		byte[] body = responseBody.getBytes(StandardCharsets.UTF_8);
		exchange.sendResponseHeaders(responseStatus, body.length);
		exchange.getResponseBody().write(body);
		exchange.close();
	}

	private Map<String, String> config() {
		Map<String, String> c = new HashMap<>();
		c.put("simulation", "false");
		c.put("forceHttpsApiUrl", "false"); // permit http loopback for the hermetic test
		c.put("apiurl", "http://127.0.0.1:" + server.getAddress().getPort() + "/send");
		c.put("senderId", "Keycloak");
		c.put("messageattribute", "text");
		c.put("receiverattribute", "to");
		c.put("senderattribute", "from");
		c.put("countrycode", "+1");
		c.put("apitokenattribute", "apikey");
		c.put("apitoken", TOKEN);
		return c;
	}

	@Test
	public void successfulSendDoesNotThrow() {
		responseStatus = 200;
		new ApiSmsService(config()).send(PHONE, OTP_MESSAGE);
	}

	@Test
	public void nonSuccessStatusFailsClosed() {
		responseStatus = 400;
		SmsDeliveryException ex = assertThrows(SmsDeliveryException.class,
			() -> new ApiSmsService(config()).send(PHONE, OTP_MESSAGE));
		// The exception propagates to the caller (and may be logged there): it must not carry secrets.
		assertFalse(ex.getMessage().contains(OTP), "delivery exception must not contain the OTP");
		assertFalse(ex.getMessage().contains("5555550100"), "delivery exception must not contain the phone");
		assertFalse(ex.getMessage().contains(TOKEN), "delivery exception must not contain the API token");
	}

	@Test
	public void transportFailureFailsClosed() {
		Map<String, String> c = config();
		c.put("apiurl", "http://127.0.0.1:1/send"); // nothing listening → connection refused
		assertThrows(SmsDeliveryException.class, () -> new ApiSmsService(c).send(PHONE, OTP_MESSAGE));
	}

	@Test
	public void errorLogsNeverLeakOtpPhoneOrToken() {
		// ApiSmsService logs under the SmsServiceFactory category (see its logger field).
		Logger jul = Logger.getLogger(SmsServiceFactory.class.getName());
		List<String> captured = new ArrayList<>();
		Handler handler = new Handler() {
			@Override public void publish(LogRecord r) {
				captured.add(r.getMessage() + " " + Arrays.toString(r.getParameters()));
			}
			@Override public void flush() {}
			@Override public void close() {}
		};
		Level previous = jul.getLevel();
		jul.addHandler(handler);
		jul.setLevel(Level.ALL);
		try {
			responseStatus = 502;
			responseBody = "gateway said: could not deliver to " + PHONE; // even an echoing gateway body
			assertThrows(SmsDeliveryException.class,
				() -> new ApiSmsService(config()).send(PHONE, OTP_MESSAGE));
		} finally {
			jul.removeHandler(handler);
			jul.setLevel(previous);
		}

		String all = String.join("\n", captured);
		assertTrue(all.contains("Failed to send"), "the send failure must be logged: " + all);
		assertFalse(all.contains(OTP), "OTP must not appear in logs: " + all);
		assertFalse(all.contains("5555550100"), "unmasked phone must not appear in logs: " + all);
		assertFalse(all.contains(TOKEN), "API token must not appear in logs: " + all);
		assertFalse(all.contains("apikey=" + TOKEN), "token must not appear in a query/body payload in logs: " + all);
	}
}
