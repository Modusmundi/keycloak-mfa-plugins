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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * A4 — phone-number log masking. With masking on the number is reduced to its last 4 digits;
 * with masking off the raw value is returned unchanged.
 */
public class PhoneNumberLogMaskerTest {

	@Test
	public void masksToLastFourDigitsWhenEnabled() {
		assertEquals(PhoneNumberLogMasker.MASK_PREFIX + "0100",
			PhoneNumberLogMasker.forLog("+15555550100", true));
	}

	@Test
	public void ignoresNonDigitsWhenComputingLastFour() {
		assertEquals(PhoneNumberLogMasker.MASK_PREFIX + "4567",
			PhoneNumberLogMasker.forLog("+1 (555) 123-4567", true));
	}

	@Test
	public void returnsRawNumberWhenDisabled() {
		assertEquals("+15555550100", PhoneNumberLogMasker.forLog("+15555550100", false));
	}

	@Test
	public void neverRevealsMoreThanFourDigits() {
		String masked = PhoneNumberLogMasker.forLog("+15555550100", true);
		assertTrue(masked.startsWith(PhoneNumberLogMasker.MASK_PREFIX), "must be masked");
		String revealed = masked.substring(PhoneNumberLogMasker.MASK_PREFIX.length());
		assertTrue(revealed.length() <= 4, "at most 4 digits revealed");
	}

	@Test
	public void tooShortNumberIsFullyMasked() {
		assertEquals(PhoneNumberLogMasker.MASK_PREFIX, PhoneNumberLogMasker.forLog("12", true));
	}

	@Test
	public void nullIsReturnedUnchanged() {
		assertNull(PhoneNumberLogMasker.forLog(null, true));
		assertNull(PhoneNumberLogMasker.forLog(null, false));
	}
}
