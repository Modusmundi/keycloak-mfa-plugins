# Resolved finding — SMS enrolment region allowlist was silently bypassed (toll-fraud)

**Severity:** HIGH (SMS toll-fraud / SMS-pumping)
**Status:** RESOLVED 2026-07-10, commit `3ac8878` (PR #7), released in `v26.6.5-fwc.7`
**Discovered:** 2026-07-10, during a security pass of a downstream distribution that ships this module's jar

## The bug

The `allowedRegions` phone-number allowlist — the control that stops MFA enrolment from sending SMS to
premium-rate or out-of-region numbers — was only enforced when both of two unrelated formatting toggles
were on, and both default to `false`:

- `normalizePhoneNumber` (default `false`)
- `forceRetryOnBadFormat` (default `false`)

The region and number-type checks lived inside `PhoneNumberRequiredAction.formatPhoneNumber`, which only
ran when `normalizePhoneNumber` was on, and whose "reject" verdict (`null` return) was only honored when
`forceRetryOnBadFormat` was also on. In every other configuration a number outside the allowlist was
stored and texted anyway. With `normalizePhoneNumber=true` and `forceRetryOnBadFormat=false`, the check
even logged `region ... is not in the allowed regions` while the SMS still went out, so log-based
monitoring looked like the control was working.

Because enrolment is the path where the user chooses the destination number, a configured allowlist gave
no protection in the default configuration: an attacker could enrol a premium-rate or foreign number and
have Keycloak send the code — plus every resend, repeatable across fresh sessions. The config help text
acknowledged the `normalizePhoneNumber` coupling but not the second one, and a documented caveat on a
security control is not a substitute for fail-closed enforcement.

## The fix

The region/type/validity logic was refactored out of the formatting path into a shared
`parseAndValidatePhoneNumber` plus a boolean `validateRegionAndType`, and a standalone fail-closed gate
was added in `PhoneNumberRequiredAction.processAction`: whenever `allowedRegions` or `numberTypeFilters`
is configured, a number that is out-of-region, of a disallowed type, invalid, or unparseable is rejected
with a re-prompt — regardless of the two formatting toggles. The formatting path itself is unchanged, so
existing best-effort-normalisation configs behave as before. The config help text was corrected to drop
the "only applied when Format phone number is enabled" caveat.

## Verification

- `PhoneNumberRegionEnforcementTest` covers the full flag matrix: an out-of-region number is rejected in
  all three previously-bypassed combinations, an in-region number is accepted, unparseable numbers are
  rejected, the number-type filter is enforced, and the no-allowlist configuration keeps its old behavior.
- Verified end-to-end in a Keycloak 26.6.3 container with the default config
  (`normalizePhoneNumber=false`, `forceRetryOnBadFormat=false`, `allowedRegions=US`): before the fix a
  `+44` number was accepted and texted; after the fix it is rejected with no send, while a `+1` number
  still enrols.

See also §9 of the repository-wide [SECURITY-AUDIT.md](../SECURITY-AUDIT.md).
