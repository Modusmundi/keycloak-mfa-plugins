# Keycloak Email Authenticator

> **Status: not built, released, or maintained.** This module is excluded from the Maven build and
> from releases; it is kept in the tree for reference only. The last release containing its jar is
> `v26.6.5-fwc.7`.

Keycloak Authentication Provider implementation that sends a one-time code (OTP) via email using the SMTP server configured in the Keycloak realm.

## Installing
1. Download the latest `netzbegruenung.email-authenticator-*.jar` from this repository's releases page.
2. Copy the jar into the `providers` directory of your Keycloak:
   ```shell
   cp netzbegruenung.email-authenticator-*.jar /path/to/keycloak/providers
   ```
3. Run the `build` command and restart Keycloak:
   ```shell
   /path/to/keycloak/bin/kc.sh build [your-additional-flags]
   systemctl restart keycloak.service
   ```

## Setup
1. Log in to the Keycloak Admin Console and select your realm.
2. Make sure the realm's **Email** settings point to a working SMTP server.
3. Go to **Authentication** in the left sidebar and select the flow you want to use (e.g. `browser`).
4. Since built-in flows are read-only, duplicate the flow if you haven't already: click the three dots in the top right of the flow details and select **Duplicate**.
5. In your new flow, click **Add step**.
6. Search for `Email Authentication (2FA)` and click **Add**.
7. Set the requirement to `Alternative` (or `Required` to enforce it).
8. Click the **Actions** menu (three dots) next to the `Email Authentication (2FA)` step and select **Config**. The following options are available:

| Parameter | Description | Default |
| --- | --- | --- |
| Code length | Number of digits of the generated OTP. | `6` |
| Time-to-live | Validity period of the OTP in seconds. | `300` |
| Force 2FA | If no other 2FA method is configured, the user is forced to verify their email and use Email OTP. | `false` |

The email subject and body are taken from the theme message bundle (keys `emailAuthSubject` and `emailAuthText`) and can be customised per realm/theme. The body supports `%1$s` (code) and `%2$d` (validity in minutes) placeholders.

## Usage
After the authenticator is wired into the flow, users with a verified email address automatically receive a login code on the second-factor step.

## Enforce Email 2FA
If the option `Force 2FA` is enabled and a user has no other 2FA method set up, Keycloak will add the built-in `VERIFY_EMAIL` required action so the user verifies their address before continuing.

## License
Apache License 2.0
