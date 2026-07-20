# Changelog

Notable changes to this repository. Versions up to `v26.6.5` come from the upstream
[netzbegruenung/keycloak-mfa-plugins](https://github.com/netzbegruenung/keycloak-mfa-plugins) project;
the `v26.6.5-fwc.*` tags are releases of this fork.

## Unreleased — v26.7.0-fwc.1

Targets Keycloak 26.7.0. Module versions move from `26.6.5` to `26.7.0` to track the platform.

- sms: fail closed on gateway delivery failure — a non-2xx response or transport error now raises
  `SmsDeliveryException`, and no call site presents a code-entry form for an SMS that never went out
- sms: the resend cooldown clock and the per-session resend ceiling count send *attempts*, not
  successes. A gateway that accepts and then times out previously left no throttle state, so every
  retry re-entered the unthrottled first-send path (unbounded outbound SMS / toll fraud)
- sms: a failed send invalidates any previously issued code, so an earlier code can no longer
  authorise a newly entered destination number
- sms: gateway error logging no longer echoes the exception message or cause chain at the call sites
  in `PhoneValidationRequiredAction`, which had defeated the host/URL redaction done at the throw site
- sms: report failed SMS codes to the brute-force protector as the `otp` category — Keycloak 26.7
  only counts categories in an allow-list, so the previous value was silently dropped and lockout
  did not engage for the SMS factor
- sms: `hideResponsePayload` now defaults to on. Realms configured before this change have the old
  value persisted and must be updated in realm config; a code default does not reach them
- enforce-mfa: an offered credential id that mapped to nothing was treated as satisfied for every
  fresh user, which skipped the whole enrollment step; unmapped ids no longer satisfy it
- enforce-mfa: match credentials by type rather than provider id
- build: drop the undeployed `email-authenticator` and `app-authenticator` modules from the Maven
  build, the dev runner and releases; their source stays in the tree as unmaintained reference code
- release: gate publication on the build, SAST (OpenGrep) and SCA (Trivy) workflows; assert exactly
  the two provider jars reach the signing stage; sign the SBOM alongside the jars
- docs: overhaul of all module READMEs, security docs relocated and condensed, SECURITY.md and this
  changelog added

## v26.6.5-fwc.7 — 2026-07-10

- sms: enforce the phone region/type allowlist (`allowedRegions`, `numberTypeFilters`) fail-closed at
  enrolment, independent of the formatting toggles (see
  [sms-authenticator/SMS-REGION-ALLOWLIST-BYPASS.md](sms-authenticator/SMS-REGION-ALLOWLIST-BYPASS.md))
- sms: bound gateway HTTP calls with connect (5 s) and request (10 s) timeouts

## v26.6.5-fwc.6 — 2026-07-09

- sms: mask phone numbers in server logs (`maskPhoneNumberInLogs`, default on)
- sms: require HTTPS on the gateway URL (`forceHttpsApiUrl`, default on; loopback HTTP allowed for
  development)
- ci: SCA workflow (Trivy) with CycloneDX SBOM, gating on CRITICAL findings; npm ecosystem added to
  Dependabot; axios bumped in the app-authenticator CLI

## v26.6.5-fwc.5 — 2026-07-09

- sms: resend button with server-side cooldown (`resendCooldownSeconds`) and per-session ceiling
  (`resendMaxCount`), covering page-refresh re-sends
- sms: constant-time code comparison
- release: cosign keyless signing of each provider jar
- ci: artifact retention limits and Renovate config

## v26.6.5-fwc.4 — 2026-06-27

- sms: enforce brute-force lockout on the enrollment-validation path

## v26.6.5-fwc.3 — 2026-06-26

- sms: guard missing config and empty OTP submission against NPE
- ci: pin GitHub Actions to commit SHAs

## v26.6.5-fwc.2 — 2026-06-26

- ci: grant the release job permission to publish release assets

## v26.6.5-fwc.1 — 2026-06-26

- sms: `allowedRegions` config to restrict SMS enrolment by phone region
- sms: lock out repeated invalid SMS codes via the realm brute-force protector
- sms: vault support (`${vault.<key>}`) for the gateway API token and Basic Auth username
- ci: SAST workflow (OpenGrep), gating

## v26.6.5 — 2026-05-22

- version bump; last upstream release this fork is based on

## v26.6.4 — 2026-05-22

- app-auth: ensure auth note is cleared after sending

## v26.6.3 — 2026-05-22

- earlier history is in the upstream project
