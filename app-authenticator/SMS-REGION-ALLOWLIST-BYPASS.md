# Security recommendation — SMS enrollment region allowlist is silently bypassed (toll-fraud)

**Severity:** HIGH (SMS toll-fraud / SMS-pumping)
**Status:** RESOLVED (2026-07-10) — Option A applied on branch `security/sms-pci-hardening`. The region/type
allowlist is now enforced fail-closed at enrolment via a standalone gate (`validateRegionAndType`) in
`PhoneNumberRequiredAction.processAction`, independent of `normalizePhoneNumber` / `forceRetryOnBadFormat`.
Covered by `PhoneNumberRegionEnforcementTest` (flag matrix) and verified end-to-end in a Keycloak 26.6.3
container: before the fix a `+44` number was accepted and texted in the default config; after, it is
rejected with no send while a `+1` number still enrols. See `SECURITY-AUDIT.md` §9.
**Discovered:** downstream security pass of the `kcl-private` Keycloak image, which bakes this fork's signed
`sms-authenticator` jar (release `v26.6.5-fwc.6`, sha512-pinned and cosign-verified).

> **Note on file location.** This document is staged in `app-authenticator/` for handoff convenience, but the
> vulnerable code and the fix are in the **`sms-authenticator/`** module. An agent acting on this must edit
> files under `sms-authenticator/src/main/java/netzbegruenung/keycloak/authenticator/`, not `app-authenticator/`.

---

## TL;DR

The `allowedRegions` phone-number allowlist — the control that stops MFA enrollment from sending SMS to
premium-rate or out-of-region numbers — is only enforced when **both** of two *other* config toggles are on,
and **both default to `false`**:

- `normalizePhoneNumber` (default `false`)
- `forceRetryOnBadFormat` (default `false`)

If either is off, a user enrolling MFA can supply a phone number in a disallowed region and the code is sent
there anyway. Because enrollment is the path where the *attacker chooses the destination number*, a configured
allowlist that reads as "protected" provides **zero** protection in the default configuration. This is a
toll-fraud / SMS-pumping primitive (initial code + every resend, repeatable across sessions).

---

## Affected code

Module: `sms-authenticator`

| File | Location | Role |
|---|---|---|
| `.../authenticator/PhoneNumberRequiredAction.java` | `processAction(...)` ~L198–226 | Enrollment: decides whether to accept/store the entered number |
| `.../authenticator/PhoneNumberRequiredAction.java` | `formatPhoneNumber(...)` ~L236–316 | Where the `allowedRegions` (and `numberTypeFilters`) check actually lives |
| `.../authenticator/SmsAuthenticatorFactory.java` | config props L102 / L105 / L107 | Declares the two flags (`BOOLEAN_TYPE`, default `false`) and `allowedRegions` |

Config is read from the authenticator config aliased **`sms-2fa`** (`getAuthenticatorConfigByAlias("sms-2fa")`).

---

## Mechanics

### `processAction` (enrollment) — where the enforcement is lost

```java
// PhoneNumberRequiredAction.java ~L198
AuthenticatorConfigModel config = context.getRealm().getAuthenticatorConfigByAlias("sms-2fa");
boolean normalizeNumber = false;
boolean forceRetryOnBadFormat = false;
...
if (config != null && config.getConfig() != null) {
    normalizeNumber       = Boolean.parseBoolean(config.getConfig().getOrDefault("normalizePhoneNumber", "false"));
    forceRetryOnBadFormat = Boolean.parseBoolean(config.getConfig().getOrDefault("forceRetryOnBadFormat", "false"));
    ...
}

// L209
if (normalizeNumber) {                                                 // GATE 1: block runs only if normalize on
    String formattedNumber = formatPhoneNumber(context, mobileNumber); // allowedRegions check lives inside here
    if (formattedNumber != null && !formattedNumber.isBlank()) {
        mobileNumber = formattedNumber;                                // allowed → store normalized E.164
    } else if (forceRetryOnBadFormat) {                                // GATE 2: reject only if forceRetry on
        ...
        handleInvalidNumber(context, formatError);
        return;                                                        // the ONLY path that blocks enrollment
    }
    // else: formattedNumber == null (rejected) AND forceRetry == false → FALL THROUGH, mobileNumber unchanged
}

authSession.setAuthNote("mobile_number", mobileNumber);                // L223: stores raw number on the bypass path
...
context.success();                                                     // L226: enrollment proceeds → SMS is sent
```

### `formatPhoneNumber` — the region check correctly detects, then its verdict is discarded

```java
// PhoneNumberRequiredAction.java ~L272
String allowedRegionsString = config.getConfig().getOrDefault("allowedRegions", "");
if (allowedRegionsString != null && !allowedRegionsString.isBlank()) {
    String region = phoneNumberUtil.getRegionCodeForNumber(originalPhoneNumberParsed);
    boolean regionAllowed = false;
    for (String allowedRegion : allowedRegionsString.split("##|,")) {
        if (allowedRegion.trim().equalsIgnoreCase(region)) { regionAllowed = true; break; }
    }
    if (!regionAllowed) {
        logger.errorf("Phone number region %s is not in the allowed regions [%s]", region, allowedRegionsString);
        context.getAuthenticationSession().setAuthNote("formatError", "numberFormatRegionNotAllowed");
        return null;                                                   // signals "reject"
    }
}
```

`formatPhoneNumber` parses with a configurable default region (`countrycode`, default `49`/DE), runs
`isValidNumber`, then the region and type filters. Any failure returns `null` after setting a `formatError`
authNote. The `null` is the "reject" signal — but `processAction` only honors it when `forceRetryOnBadFormat`
is on.

### Two distinct failure modes

| Config | `formatPhoneNumber` called? | Region violation detected? | Result |
|---|---|---|---|
| `normalizePhoneNumber = false` (default) | No | No — check never runs | Raw number stored; **allowlist completely inert, no log** |
| `normalize = true`, `forceRetryOnBadFormat = false` (default) | Yes | **Yes** — even logs `region ... not in the allowed regions` | `null` returned, but neither `if` branch runs → falls through → **raw number stored and texted** |
| `normalize = true`, `forceRetryOnBadFormat = true` | Yes | Yes | `handleInvalidNumber` + `return` → **correctly blocked** (only safe config) |

The second row is the more dangerous one: the control fires, writes an **error log**, and the SMS *still* goes
out — so log-based monitoring looks like it's working while the number is accepted.

The `allowedRegions` property description (Factory L107) already says *"Only applied when 'Format phone number'
is enabled"*, acknowledging the `normalizePhoneNumber` coupling — but it does **not** mention the
`forceRetryOnBadFormat` coupling, and a documented caveat on a security control is not a substitute for
fail-closed enforcement.

---

## Impact

- **Toll-fraud / SMS-pumping.** During MFA enrollment (or a phone-number update) the user supplies the
  destination number. With `allowedRegions` configured but the default flags, an attacker enrolls a
  premium-rate or foreign number and Keycloak sends the code there — plus every **resend** (fwc.5 resend
  feature), repeatable across unlimited fresh sessions. Direct Twilio cost and potential revenue-share abuse.
- **False sense of protection.** Operators enable `allowedRegions` *specifically* to prevent this. The control
  silently not applying is worse than not having it, because it removes the incentive to add a compensating
  control elsewhere.

---

## How this was verified

- Read the control flow at the source (this repo). The bypass is unambiguous from `processAction` +
  `formatPhoneNumber`.
- Confirmed the defaults: `SmsAuthenticatorFactory` L102 `normalizePhoneNumber` → `false`, L105
  `forceRetryOnBadFormat` → `false` (both `BOOLEAN_TYPE`).
- Tied to the shipped artifact: the `sms-authenticator` jar baked into `kcl-private` has a sha512 matching the
  `v26.6.5-fwc.6` release pin, and the released jar contains the region-filter code path
  (`numberFormatRegionNotAllowed`). Current fork HEAD authenticator code is identical to that release.
- Not yet reproduced via a live enrollment (would require a realm with the SMS flow + an `allowedRegions`
  config). A live repro recipe is in the last section for whoever implements the fix.

---

## Fix — two options

Both fail closed. They differ only in whether configuring an allowlist should also change number *storage*
and global format-validation behavior.

### Option A (recommended) — make the allowlist a standalone gate, independent of the two flags

Enforce region/type whenever an allowlist/type-filter is configured, regardless of `normalizePhoneNumber` and
`forceRetryOnBadFormat`. This keeps those two flags meaning exactly what they say (E.164 rewrite-and-store;
reprompt-on-any-format-error) and stops the security control from riding inside the formatting path.

Sketch (adapt to the real parse code in `formatPhoneNumber`, which uses the `countrycode` default region):

```java
// In processAction, BEFORE the existing `if (normalizeNumber)` block:
String allowedRegions   = cfg.getOrDefault("allowedRegions", "");
String numberTypeFilters = cfg.getOrDefault("numberTypeFilters", "");
boolean allowlistConfigured = !allowedRegions.isBlank() || !numberTypeFilters.isBlank();

if (allowlistConfigured) {
    // Parse ONLY to inspect region/type — do NOT reassign mobileNumber (no forced E.164 storage).
    // Reuse the parse + isValidNumber + region + type logic from formatPhoneNumber, refactored to a
    // boolean validator, e.g. validateRegionAndType(context, mobileNumber) that returns false + sets the
    // formatError authNote on any violation OR unparseable/invalid input (fail-closed).
    if (!validateRegionAndType(context, mobileNumber)) {
        String formatError = authSession.getAuthNote("formatError");
        handleInvalidNumber(context, formatError != null ? formatError : "numberFormatRegionNotAllowed");
        return;
    }
}

// Existing behavior unchanged — normalization stays a separate, admin-controlled preference:
if (normalizeNumber) {
    String formattedNumber = formatPhoneNumber(context, mobileNumber);
    if (formattedNumber != null && !formattedNumber.isBlank()) {
        mobileNumber = formattedNumber;
    } else if (forceRetryOnBadFormat) {
        ... // unchanged
        handleInvalidNumber(context, formatError); return;
    }
}
```

Implementation note: factor the region/type portion of `formatPhoneNumber` into a `validateRegionAndType(...)`
that returns a boolean (and sets `formatError`), so both the new gate and the existing normalization path call
the same logic — no duplicated allowlist parsing. A number that can't be parsed or fails `isValidNumber` must
count as a violation (fail-closed).

**Pros:** allowlist means what it says regardless of other toggles; no surprise E.164 rewrite of stored
numbers; strict parse-or-reject applies only where security requires it (allowlist configured).
**Cons:** slightly larger refactor of `formatPhoneNumber`.

### Option B (simpler) — force both flags on whenever an allowlist is configured

At config read-time in `processAction`, if `allowedRegions` (or `numberTypeFilters`) is non-empty, override
both booleans to `true`:

```java
boolean allowlistConfigured =
    !config.getConfig().getOrDefault("allowedRegions", "").isBlank()
 || !config.getConfig().getOrDefault("numberTypeFilters", "").isBlank();
if (allowlistConfigured) {
    normalizeNumber       = true;   // so formatPhoneNumber runs and the region check executes
    forceRetryOnBadFormat = true;   // so a rejection actually blocks
}
```

**Pros:** minimal diff.
**Cons:** turning on `normalizePhoneNumber` also **rewrites and stores** the number in E.164 (a data-format
change for every enrollee), and `forceRetryOnBadFormat` makes *any* format failure a hard reprompt for
everyone — both are behavior changes beyond "enforce the allowlist." Also, **silently** overriding admin-set
`false` values is confusing: the next operator sees `forceRetryOnBadFormat = false` in the config and can't
explain why enforcement happens. If you take this route, prefer making the coupling **explicit** rather than
silent — reject the config at save time (Factory/`Configure...` validation) with a message like *"allowedRegions
requires normalizePhoneNumber and forceRetryOnBadFormat to be enabled"* — so the admin sees and acknowledges it.

### Recommendation

Prefer **Option A**. A security control (region allowlist) should not be conditional on unrelated formatting
preferences, and it should not drag in E.164 storage rewriting as a side effect. If Option B is chosen for
speed, pair it with explicit config validation (not silent override) and document the storage-format change.

---

## Tests to add (`sms-authenticator` module)

Cover the enrollment path (`PhoneNumberRequiredAction.processAction`) with `allowedRegions` set to a single
region (e.g. `US`) and assert an out-of-region number is **rejected** across the flag matrix:

1. `normalize=false, forceRetry=false` → rejected (currently: accepted — the bug).
2. `normalize=true,  forceRetry=false` → rejected (currently: accepted — the bug).
3. `normalize=true,  forceRetry=true`  → rejected (already works; guard against regression).
4. In-region number → accepted in all of the above.
5. Unparseable / invalid number with an allowlist configured → rejected (fail-closed).

---

## Live reproduction recipe (for whoever implements the fix)

Against a Keycloak with this jar (e.g. the `kcl-private` image, or a stock Keycloak with the provider
dropped in):

1. Configure the `sms-2fa` authenticator config: set `allowedRegions=US`, leave `normalizePhoneNumber` and
   `forceRetryOnBadFormat` at default (unchecked). Keep `simulation=true` (default) so sends are logged, not
   actually dispatched.
2. Trigger phone enrollment (the `mobile_number_config` / update-phone required action) for a test user.
3. Enter a non-US number (e.g. a UK `+44...`).
4. Observe the server log: with the bug, you'll see `Phone number region GB is not in the allowed regions
   [US]` **and** a subsequent `Would send SMS to +44...` — i.e. the code is sent to the disallowed number
   despite the allowlist. After the fix, enrollment is rejected and no send is logged.

---

## Related SMS findings (separate items, same module — for context, not part of this fix)

- OTP code + gateway secret logged on send failure (`ApiSmsService`); `simulation` defaults `true` and logs
  the OTP + unmasked phone (`SmsAuthenticatorFactory` L78). Consider defaulting `simulation` to `false` and
  redacting code/token in failure logs.
- No cross-session SMS send cap (resend limits are per-auth-session notes only); SMS brute-force protection
  no-ops unless the realm has brute-force protection enabled. Consider an independent per-user/per-phone send
  and attempt ceiling.
- Release workflow hardening: `release.yml` lacks a `cosign-release:` pin (installer could drift to cosign v4
  and break downstream detached-sidecar verify) and doesn't gate the release on the SAST/checks suite — both
  present in the `kcl-spis` release workflow; recommend backporting.
