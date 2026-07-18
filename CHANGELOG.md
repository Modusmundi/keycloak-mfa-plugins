# Changelog

Notable changes to this repository. Versions up to `v26.6.5` come from the upstream
[netzbegruenung/keycloak-mfa-plugins](https://github.com/netzbegruenung/keycloak-mfa-plugins) project;
the `v26.6.5-fwc.*` tags are releases of this fork.

## Unreleased

- build: drop the undeployed `email-authenticator` and `app-authenticator` modules from the Maven
  build, the dev runner and releases; their source stays in the tree as unmaintained reference code
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
