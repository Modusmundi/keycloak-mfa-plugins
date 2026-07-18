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
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @author Netzbegruenung e.V.
 * @author verdigado eG
 */

package netzbegruenung.keycloak.authenticator;

import com.google.common.base.Splitter;
import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber.PhoneNumber;
import jakarta.ws.rs.core.Response;
import netzbegruenung.keycloak.authenticator.credentials.SmsAuthCredentialModel;
import org.jboss.logging.Logger;
import org.keycloak.authentication.CredentialRegistrator;
import org.keycloak.authentication.InitiatedActionSupport;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.authentication.requiredactions.WebAuthnRegisterFactory;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.WebAuthnCredentialModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Stream;

public class PhoneNumberRequiredAction implements RequiredActionProvider, CredentialRegistrator {

	public static final String PROVIDER_ID = "mobile_number_config";

	private static final Logger logger = Logger.getLogger(PhoneNumberRequiredAction.class);
	private static final Splitter numberFilterSplitter = Splitter.on("##");
	private static final Pattern nonDigitPattern = Pattern.compile("[^0-9+]");
	private static final Pattern whitespacePattern = Pattern.compile("\\s+");

	@Override
	public InitiatedActionSupport initiatedActionSupport() {
		return InitiatedActionSupport.SUPPORTED;
	}

	@Override
	public void evaluateTriggers(RequiredActionContext context) {
		// TODO: get the alias from somewhere else or move config into realm or application scope
		AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
		if (config == null) {
			logger.error("Failed to check 2FA enforcement, no config alias sms-2fa found");
			return;
		}
		boolean forceSecondFactorEnabled = Boolean.parseBoolean(config.getConfig().get("forceSecondFactor"));
		if (forceSecondFactorEnabled) {
			if (config.getConfig().get("whitelist") != null) {
				RoleModel whitelistRole = context.getRealm().getRole(config.getConfig().get("whitelist"));
				if (whitelistRole == null) {
					logger.errorf(
						"Failed configured whitelist role check [%s], make sure that the role exists",
						config.getConfig().get("whitelist")
					);
				} else if (context.getUser().hasRole(whitelistRole)) {
					// skip enforcement if user is whitelisted
					return;
				}
			}
			// add auth note for phone number input placeholder
			context.getAuthenticationSession().setAuthNote("mobileInputFieldPlaceholder",
				config.getConfig().getOrDefault("mobileInputFieldPlaceholder", ""));

			// list of accepted 2FA alternatives
			List<String> secondFactors = Arrays.asList(
				SmsAuthCredentialModel.TYPE,
				WebAuthnCredentialModel.TYPE_TWOFACTOR,
				OTPCredentialModel.TYPE
			);
			Stream<CredentialModel> credentials = context
				.getUser()
				.credentialManager()
				.getStoredCredentialsStream();
			if (credentials.anyMatch(x -> secondFactors.contains(x.getType()))) {
				// skip as 2FA is already set
				return;
			}

			Set<String> availableRequiredActions = Set.of(
				PhoneNumberRequiredAction.PROVIDER_ID,
				PhoneValidationRequiredAction.PROVIDER_ID,
				UserModel.RequiredAction.CONFIGURE_TOTP.name(),
				WebAuthnRegisterFactory.PROVIDER_ID,
				UserModel.RequiredAction.UPDATE_PASSWORD.name()
			);
			Set<String> authSessionRequiredActions = context.getAuthenticationSession().getRequiredActions();
			authSessionRequiredActions.retainAll(availableRequiredActions);
			if (!authSessionRequiredActions.isEmpty()) {
				// skip as relevant required action is already set
				return;
			}

			Stream<String> usersRequiredActions = context.getUser().getRequiredActionsStream();
			if (usersRequiredActions.noneMatch(availableRequiredActions::contains)) {
				logger.infof(
					"No 2FA method configured for user: %s, setting required action for SMS authenticator",
					context.getUser().getUsername()
				);
				context.getUser().addRequiredAction(PhoneNumberRequiredAction.PROVIDER_ID);
			}
		}
	}

	/**
	 * Generates a list of country codes with their names and emojis to be displayed in the phone number input form.
	 *
	 * @param context the current RequiredActionContext
	 * @return a list of maps containing country name, code, and emoji
	 */
	public List<Map<String, String>> getCountryCodeList(RequiredActionContext context) {
		AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
		// No 'sms-2fa' config → fall back to the full country list instead of NPEing on the form render.
		String countryCodeList = (config == null || config.getConfig() == null)
			? "" : config.getConfig().getOrDefault("countryCodeList", "");

		UserModel user = context.getUser();
		KeycloakSession session = context.getSession();
		Locale locale = session.getContext().resolveLocale(user);

		PhoneNumberUtil phoneUtil = PhoneNumberUtil.getInstance();

		List<Map<String, String>> countryList = new ArrayList<>();
		if (!countryCodeList.isBlank()) {
			List<String> countryCodes = Arrays.asList(countryCodeList.split(","));
			for (String countryCode : countryCodes) {
				try {
					String code = "+" + Integer.toString(phoneUtil.getCountryCodeForRegion(countryCode.trim().toUpperCase()));
					String countryName = new Locale("", countryCode.trim().toUpperCase()).getDisplayCountry(locale);

					// generate emoji from country code
					int offset = 0x1F1E6;  // Base Unicode for regional indicator symbols
					int codePoint1 = offset + (countryCode.trim().toUpperCase().charAt(0) - 'A');
					int codePoint2 = offset + (countryCode.trim().toUpperCase().charAt(1) - 'A');
					String emoji = new String(new int[]{codePoint1, codePoint2}, 0, 2);

					countryList.add(Map.of("name", countryName, "code", code, "emoji", emoji));
					logger.infof("Added country code %s for country %s", code, countryName);
				} catch (Exception e) {
					logger.errorf("Failed to get country code for country %s", countryCode, e);
				}
			}
		}

		return countryList;
	}

	@Override
	public void requiredActionChallenge(RequiredActionContext context) {
		Response challenge = context.form()
			.setAttribute("mobileInputFieldPlaceholder", context.getAuthenticationSession().getAuthNote("mobileInputFieldPlaceholder"))
			.setAttribute("countryList", getCountryCodeList(context))
			.createForm("mobile_number_form.ftl");
		context.challenge(challenge);
	}

	@Override
	public void processAction(RequiredActionContext context) {
		AuthenticationSessionModel authSession = context.getAuthenticationSession();

		// Guard a missing/blank 'mobile_number' form field (e.g. a malformed POST) instead of
		// dereferencing null in the regex matcher below, which would surface as an unhandled 500.
		// Re-prompt the enrolment form, the same as any invalid number.
		String rawMobileNumber = context.getHttpRequest().getDecodedFormParameters().getFirst("mobile_number");
		if (rawMobileNumber == null || rawMobileNumber.isBlank()) {
			handleInvalidNumber(context, "numberFormatNumberInvalid");
			return;
		}
		String mobileNumber = nonDigitPattern.matcher(rawMobileNumber).replaceAll("");

		// get the country code from the select input if available and add it to the mobile number
		if (context.getHttpRequest().getDecodedFormParameters().getFirst("country_code") != null) {
			String countryCode = nonDigitPattern.matcher(context.getHttpRequest().getDecodedFormParameters().getFirst("country_code")).replaceAll("");
			mobileNumber = countryCode + mobileNumber.replaceAll("^0+", "");
		}

		// get the phone number formatting values from the config
		AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
		boolean normalizeNumber = false;
		boolean forceRetryOnBadFormat = false;
		boolean maskPhoneInLogs = true;
		boolean allowlistConfigured = false;
		if (config != null && config.getConfig() != null) {
			normalizeNumber = Boolean.parseBoolean(config.getConfig().getOrDefault("normalizePhoneNumber", "false"));
			forceRetryOnBadFormat = Boolean.parseBoolean(config.getConfig().getOrDefault("forceRetryOnBadFormat", "false"));
			maskPhoneInLogs = Boolean.parseBoolean(config.getConfig().getOrDefault("maskPhoneNumberInLogs", "true"));
			allowlistConfigured = !config.getConfig().getOrDefault("allowedRegions", "").isBlank()
				|| !config.getConfig().getOrDefault("numberTypeFilters", "").isBlank();
		}

		// SECURITY (anti-toll-fraud): when an allowed-region or number-type allowlist is configured,
		// enforce it fail-closed here — independent of the normalizePhoneNumber / forceRetryOnBadFormat
		// formatting toggles. Previously the region/type checks only took effect inside the
		// normalization path AND only rejected when forceRetryOnBadFormat was on, so a configured
		// allowlist silently no-opped in the default configuration and a disallowed (e.g.
		// premium-rate / out-of-region) number could be enrolled and texted.
		if (allowlistConfigured && !validateRegionAndType(context, mobileNumber)) {
			String formatError = authSession.getAuthNote("formatError");
			logger.warnf("Rejected phone-number enrolment: number fails the configured region/type allowlist for user %s",
				context.getUser().getUsername());
			handleInvalidNumber(context, formatError != null && !formatError.isBlank() ? formatError : "numberFormatRegionNotAllowed");
			return;
		}

		// try to format the phone number
		if (normalizeNumber) {
			String formattedNumber = formatPhoneNumber(context, mobileNumber);
			if (formattedNumber != null && !formattedNumber.isBlank()) {
				mobileNumber = formattedNumber;
			} else if (forceRetryOnBadFormat) {
				logger.errorf("Failed phone number formatting checks for: %s", PhoneNumberLogMasker.forLog(mobileNumber, maskPhoneInLogs));
				String formatError = context.getAuthenticationSession().getAuthNote("formatError");
				if (formatError != null && !formatError.isBlank()) {
					handleInvalidNumber(context, formatError);
					return;
				}
			}
		}

		authSession.setAuthNote("mobile_number", mobileNumber);
		logger.infof("Add required action for phone validation: [%s], user: %s", PhoneNumberLogMasker.forLog(mobileNumber, maskPhoneInLogs), context.getUser().getUsername());
		context.getAuthenticationSession().addRequiredAction(PhoneValidationRequiredAction.PROVIDER_ID);
		context.success();
	}

	/**
	 * Formats the provided mobile phone number to E164 standard.
	 *
	 * @param context		the current RequiredActionContext
	 * @param mobileNumber	the mobile phone number to be formatted
	 * @return				the formatted mobile phone number, null if the phone number is invalid or mobileNumber if the config was not found
	 */
	private String formatPhoneNumber(RequiredActionContext context, String mobileNumber) {
		AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
		if (config == null || config.getConfig() == null) {
			logger.error("Failed format phone number, no config alias sms-2fa found");
			return mobileNumber;
		}
		PhoneNumber parsed = parseAndValidatePhoneNumber(context, config.getConfig(), mobileNumber);
		if (parsed == null) {
			return null;
		}
		// return the E164 format of the mobile number
		return PhoneNumberUtil.getInstance().format(parsed, PhoneNumberUtil.PhoneNumberFormat.E164);
	}

	/**
	 * True when {@code mobileNumber} satisfies every configured phone-number policy check (valid
	 * number, allowed region, allowed number type). This is a SECURITY gate — the region/type
	 * allowlist is anti-toll-fraud — so it fails <em>closed</em>: an unparseable, invalid, or
	 * out-of-policy number returns {@code false} and records the specific {@code formatError}
	 * auth-note. When the {@code sms-2fa} config is absent the number cannot be validated, which
	 * also fails closed.
	 *
	 * <p>Unlike {@link #formatPhoneNumber}, this does not rewrite the number and is independent of
	 * the {@code normalizePhoneNumber} / {@code forceRetryOnBadFormat} formatting toggles, so a
	 * configured allowlist is enforced regardless of those preferences.
	 */
	private boolean validateRegionAndType(RequiredActionContext context, String mobileNumber) {
		AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
		if (config == null || config.getConfig() == null) {
			logger.error("Cannot validate phone number region/type: no config alias sms-2fa found");
			context.getAuthenticationSession().setAuthNote("formatError", "numberFormatNumberInvalid");
			return false;
		}
		return parseAndValidatePhoneNumber(context, config.getConfig(), mobileNumber) != null;
	}

	/**
	 * Parses {@code mobileNumber} against the config's default country region and applies the
	 * validity, allowed-region, and number-type-filter checks. Returns the parsed {@link PhoneNumber}
	 * when it passes every configured check, or {@code null} (after setting the {@code formatError}
	 * auth-note) on any failure — unparseable input, an invalid number, a disallowed region, or a
	 * disallowed number type. Shared by {@link #formatPhoneNumber} and {@link #validateRegionAndType}
	 * so the allowlist logic lives in exactly one place.
	 */
	private PhoneNumber parseAndValidatePhoneNumber(RequiredActionContext context, Map<String, String> cfg, String mobileNumber) {
		final PhoneNumberUtil phoneNumberUtil = PhoneNumberUtil.getInstance();
		int countryNumber;
		// try to get the country code from the country number in the config, fallback on default DE
		try {
			countryNumber = Integer.parseInt(whitespacePattern.matcher(cfg
				.getOrDefault("countrycode", "49").replace("+", ""))
				.replaceAll(""));
		} catch (NumberFormatException e) {
			logger.warn("Failed to parse countrycode to int, using default value (49)", e);
			countryNumber = 49;
		}
		String nameCodeToUse = phoneNumberUtil.getRegionCodeForCountryCode(countryNumber);
		PhoneNumber originalPhoneNumberParsed;

		// parse the mobile number and store it as instance of PhoneNumber
		try {
			originalPhoneNumberParsed = phoneNumberUtil.parse(mobileNumber, nameCodeToUse);
		} catch (NumberParseException e) {
			logger.error("Failed to parse phone number", e);
			context.getAuthenticationSession().setAuthNote("formatError", "numberFormatFailedToParse");
			return null;
		}

		if (!phoneNumberUtil.isValidNumber(originalPhoneNumberParsed)) {
			logger.error("Phone number is not valid");
			context.getAuthenticationSession().setAuthNote("formatError", "numberFormatNumberInvalid");
			return null;
		}

		// apply allowed-region filter: reject numbers whose region is not in the configured allowlist
		String allowedRegionsString = cfg.getOrDefault("allowedRegions", "");
		if (allowedRegionsString != null && !allowedRegionsString.isBlank()) {
			String region = phoneNumberUtil.getRegionCodeForNumber(originalPhoneNumberParsed);
			boolean regionAllowed = false;
			for (String allowedRegion : allowedRegionsString.split("##|,")) {
				if (allowedRegion.trim().equalsIgnoreCase(region)) {
					regionAllowed = true;
					break;
				}
			}
			if (!regionAllowed) {
				logger.errorf("Phone number region %s is not in the allowed regions [%s]", region, allowedRegionsString);
				context.getAuthenticationSession().setAuthNote("formatError", "numberFormatRegionNotAllowed");
				return null;
			}
		}

		// apply ValidNumberType filters
		// extract number types from the filter string
		String numberFiltersString = cfg.getOrDefault("numberTypeFilters", "");
		if (numberFiltersString != null && !numberFiltersString.isBlank()) {
			List<PhoneNumberUtil.PhoneNumberType> numberTypeFilters = new ArrayList<>();
			try {
				numberFilterSplitter.splitToStream(numberFiltersString).forEach(filterString ->
					numberTypeFilters.add(PhoneNumberUtil.PhoneNumberType.valueOf(filterString.trim())));
			} catch (IllegalArgumentException e) {
				// SECURITY (anti-toll-fraud): a malformed number-type allowlist must fail CLOSED. Previously
				// the list was cleared and type enforcement silently skipped, so a disallowed (e.g.
				// premium-rate) number would be accepted whenever the filter was misconfigured. Reject the
				// enrolment instead; the admin sees the precise cause in the log below.
				logger.errorf("Illegal numberTypeFilters config: %s. Rejecting enrolment (fail closed). Valid values are a "
					+ "'##'-delimited list of FIXED_LINE, MOBILE, FIXED_LINE_OR_MOBILE, PAGER, TOLL_FREE, PREMIUM_RATE, "
					+ "SHARED_COST, PERSONAL_NUMBER, VOIP, UAN, VOICEMAIL", numberFiltersString);
				context.getAuthenticationSession().setAuthNote("formatError", "numberFormatNoMatchingFilters");
				return null;
			}

			// check to see if the number type matches any of the filters set
			PhoneNumberUtil.PhoneNumberType numberType = phoneNumberUtil.getNumberType(originalPhoneNumberParsed);
			if (numberTypeFilters.stream().noneMatch(filter -> filter == numberType)) {
				logger.errorf("Phone number type %s does not match any filters in %s", numberType.toString(), numberTypeFilters);
				context.getAuthenticationSession().setAuthNote("formatError", "numberFormatNoMatchingFilters");
				return null;
			}
		}

		return originalPhoneNumberParsed;
	}

	private void handleInvalidNumber(RequiredActionContext context, String formatError) {
		Response challenge = context
			.form()
			.setAttribute("mobileInputFieldPlaceholder", context.getAuthenticationSession().getAuthNote("mobileInputFieldPlaceholder"))
			.setAttribute("countryList", getCountryCodeList(context))
			.setError(formatError)
			.createForm("mobile_number_form.ftl");
		context.challenge(challenge);
	}

	@Override
	public void close() {}

	@Override
	public String getCredentialType(KeycloakSession keycloakSession, AuthenticationSessionModel authenticationSessionModel) {
		return SmsAuthCredentialModel.TYPE;
	}
}
