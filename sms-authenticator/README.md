# Keycloak 2FA SMS Authenticator

Keycloak Authentication Provider implementation to get a 2nd-factor authentication with an OTP/code/token sent via SMS through a configurable HTTP API.
It should be possible to interact with most SMS providers. Issues and pull requests to support more SMS providers are welcome.

This is a fork of a great demo implementation by [@dasniko](https://github.com/dasniko/keycloak-2fa-sms-authenticator), and also takes huge chunks of code
from the original authenticator provider [documentation](https://www.keycloak.org/docs/latest/server_development/index.html#_auth_spi) and [example](https://github.com/keycloak/keycloak/tree/main/examples/providers/authenticator) from Keycloak itself.

## Installing

1. Download `netzbegruenung.sms-authenticator-v<version>.jar` from this repository's releases page (or build it with `mvn clean install`, which writes it to `sms-authenticator/target/`).
2. Copy the jar into the `providers` directory of your Keycloak:
   ```shell
   cp netzbegruenung.sms-authenticator-v*.jar /path/to/keycloak/providers
   ```
3. Run the `build` command and restart Keycloak:
   ```shell
   /path/to/keycloak/bin/kc.sh build [your-additional-flags]
   systemctl restart keycloak.service
   ```

## Setup

1. Go to `/admin/master/console/#/realm/authentication/required-actions` and enable the required actions "Phone Validation" and "Update Mobile Number".
2. Navigate to your authentication flow configuration: `https://keycloak.example.com/admin/master/console/#/YOUR-REALM/authentication` and edit the `Browser flow`.
3. Add a new step next to the `OTP Form` step. Choose the `SMS Authentication (2FA)` authenticator and set it to `Alternative`.
4. Make sure that you name the alias `sms-2fa`. This is currently a hack that will hopefully be fixed: the required actions look up the authenticator config by this alias, so this first execution is used for the confirmation SMS when setting up a new phone number. Additional executions with other names can be added.
5. Open the config of the execution and configure the plugin for the HTTP API of your SMS provider. Refer to your provider's API documentation to choose the correct values.

## Configuration

### Code

| Option | Key | Default | Description |
| --- | --- | --- | --- |
| Code length | `length` | `6` | Number of digits of the generated code. |
| Time-to-live | `ttl` | `300` | Validity period of the code in seconds. |

### SMS gateway

By default the code is sent in an HTTP POST request with a JSON body. With `URL encode data` the body is form-encoded instead, and with `SMS API GET URL template` a GET request is used. The HTTP client fails a send attempt after 5 seconds if the gateway cannot be reached and after 10 seconds if it does not respond; a failed send shows the user a generic error and no code is accepted.

| Option | Key | Default | Description |
| --- | --- | --- | --- |
| SMS API URL | `apiurl` | `https://example.com/api/sms/send` | The URL that receives the HTTP request. |
| SMS API GET URL template | `getUrl` | empty | If your SMS API expects a GET request instead of POST, set a URL template with the placeholders `{phone}`, `{message}`, `{apitoken}`, `{senderId}`. If empty, a POST request is sent. |
| Force HTTPS on API URLs | `forceHttpsApiUrl` | on | Requires the API URL to use HTTPS so the code and API credentials are never sent over cleartext HTTP. Plain `http://` is only accepted for loopback hosts (`localhost`, `127.0.0.1`, `::1`) during development. Disable intentionally if you must use plaintext HTTP. |
| URL encode data | `urlencode` | off | When off, the data is sent as an `application/json` body. When on, the data is form-encoded (`application/x-www-form-urlencoded`). |
| Put API Secret Token in Authorization Header | `apiTokenInHeader` | off | If set, the API secret is sent as Authorization header; `API Secret Token Attribute` and `Basic Auth Username` are ignored. |
| API Secret Token Attribute (optional) | `apitokenattribute` | empty | Name of the attribute that contains your API token/secret. In some APIs the secret is already part of the URL path; in that case leave this empty. |
| API Secret (optional) | `apitoken` | `changeme` | Your API secret. If a Basic Auth username is set, this is the Basic Auth password. If `API Secret Token Attribute` is set, the secret is sent as the value of that attribute. |
| Basic Auth Username (optional) | `apiuser` | empty | If set, Basic Auth is performed. Leave empty if not required. |
| Message Attribute | `messageattribute` | `text` | The attribute that contains the SMS message text. For many APIs (e.g. GTX Messaging, SMS Eagle) this is `text`. |
| Receiver Phone Number Attribute | `receiverattribute` | `to` | The attribute that contains the receiver phone number. For many APIs this is `to`. |
| Receiver Phone Number Json value template | `receiverJsonTemplate` | `"%s"` | Template for the receiver value in the JSON body, in case your API expects a different structure (e.g. an array). |
| Sender Phone Number Attribute | `senderattribute` | `from` | The attribute that contains the sender phone number. Leave empty if not required. |
| SenderId | `senderId` | `Keycloak` | Displayed as the message sender on the receiving device. This is the value sent in the `Sender Phone Number Attribute`. |
| Strip + from phone number | `stripPlusPrefix` | off | Removes the leading `+` from phone numbers before sending. Required for APIs expecting E.164 without the `+` prefix (e.g. BudgetSMS). |
| Use message UUID | `useUuid` | off | Generates a UUID for the message if your API requires one. |
| UUID attribute | `uuidAttribute` | empty | The attribute that contains the generated UUID. Only applicable when `Use message UUID` is set. |
| Request JSON template | `jsonTemplate` | empty | Custom JSON body template with `%s` placeholders for UUID (if `Use message UUID` is set), phone number and message, in that order. If empty, the default template is used. |

The `API Secret` and `Basic Auth Username` values can be [Keycloak vault](https://www.keycloak.org/docs/latest/server_admin/index.html#_vault-administration) references of the form `${vault.<key>}`; plain values work unchanged.

### Resending codes

The login form offers a resend button. Both limits are enforced server-side and also cover re-sends triggered by page refreshes.

| Option | Key | Default | Description |
| --- | --- | --- | --- |
| Resend cooldown (seconds) | `resendCooldownSeconds` | `60` | Minimum seconds a user must wait between code sends within one authentication session. `0` disables the cooldown. |
| Max additional codes per session | `resendMaxCount` | `3` | Maximum number of additional codes (after the first) per authentication session. `0` hides the resend button and blocks refresh re-sends. |

### Phone number handling

`Allowed phone number regions` and `Valid number type filters` are enforced at enrolment whenever they are set, independent of the `Format phone number` and `Ask for new number if checks fail` toggles. A number outside the allowlist, of a disallowed type, or one that cannot be parsed or validated is rejected and the user is asked for a different number.

| Option | Key | Default | Description |
| --- | --- | --- | --- |
| Default country prefix | `countrycode` | `+49` | Country prefix assumed if the user does not provide one. |
| Format phone number | `normalizePhoneNumber` | off | Normalizes the phone number to the E.164 standard before storing it. |
| Ask for new number if checks fail | `forceRetryOnBadFormat` | off | Shows an error and asks the user to re-enter the phone number if the formatting checks fail. |
| Allowed phone number regions | `allowedRegions` | empty | Restricts enrolment to phone numbers from these regions (ISO 3166-1 alpha-2, e.g. `US`, `CA`, `DE`). Empty allows all regions. Note that `+1` spans several regions; add each one you want to permit. |
| Valid number type filters | `numberTypeFilters` | empty | Restricts enrolment to these phone number types. Empty allows all types. Possible values: `FIXED_LINE`, `MOBILE`, `FIXED_LINE_OR_MOBILE`, `PAGER`, `TOLL_FREE`, `PREMIUM_RATE`, `SHARED_COST`, `PERSONAL_NUMBER`, `VOIP`, `UAN`, `VOICEMAIL`. |
| List of country code | `countryCodeList` | empty | Comma-separated list of country codes (e.g. `FR,DE,GB`) shown as a select input so users can pick their country. |
| Phone number input field placeholder | `mobileInputFieldPlaceholder` | empty | Placeholder string for the phone number input field. |
| Set phone number as attribute | `storeInAttribute` | off | Also stores the phone number as a user attribute. |

### Logging and testing

| Option | Key | Default | Description |
| --- | --- | --- | --- |
| Simulation mode | `simulation` | on | The SMS is not sent but printed to the server log. Disable for production. |
| Mask phone number in logs | `maskPhoneNumberInLogs` | on | Phone numbers written to the server log are reduced to their last 4 digits. Disable only for debugging. |
| Redacted API response log message | `hideResponsePayload` | off | Does not log the API response body of the SMS send request. |

## Usage

After the authenticator and the required actions are configured, users can set up SMS authentication in the
account console under `/realms/<realm>/account/#/account-security/signing-in` by entering and confirming their phone number.

## Enforce SMS 2FA

If the option `Force 2FA` (`forceSecondFactor`, default off) is enabled and a user has no other 2FA method configured,
the user has to set up the SMS authenticator. Users with the role selected in `Excluded from enforced 2FA` (`whitelist`) are exempt.

## Security notes

Wrong codes are counted against the realm's brute-force protection (enable it in the realm settings for lockout to apply), code comparison is constant-time, and codes are generated with `SecureRandom`. A resolved enrolment-path finding is documented in [SMS-REGION-ALLOWLIST-BYPASS.md](SMS-REGION-ALLOWLIST-BYPASS.md); the repository-wide review is in the root [SECURITY-AUDIT.md](../SECURITY-AUDIT.md).
