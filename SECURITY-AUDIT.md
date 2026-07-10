# Security Audit — keycloak-mfa-plugins (SMS OTP focus)

**Date:** 2026-07-09
**Scope of this audit:** the bespoke Keycloak provider code in this repository, with primary focus on the **SMS OTP authenticator** (`sms-authenticator`), assessed for defensibility under **PCI DSS 4.0.1**. Secondary review of build/CI/dependency posture (Requirement 6).
**Context:** this repository is a temporary staging repo; the code is being handed to a separate enterprise team in a separate repository. Findings are written to travel with the code.
**Reviewed at:** branch `security/sms-pci-hardening` (off `feat/sms-resend`), Keycloak platform `26.6.2` (built), deployed/tested on Keycloak `26.6.3`.
**Deployment under test:** container `fwc-kc`, realm `billpay-poc`, flow `browser_with_sms`, SMS execution `mobile-number-authenticator` (config alias `sms-2fa`), realm brute-force protection **on** (`failureFactor=5`).

---

## 1. Executive summary

The SMS OTP authenticator is, on review, **well-built**: it uses `SecureRandom`-backed code generation, constant-time code comparison, one-time-use via code rotation, realm brute-force lockout on wrong codes, server-side resend throttling (cooldown + per-session ceiling + refresh throttling), non-enumerating error messages, and vault-aware gateway credentials. Several items initially flagged were, on closer inspection, **already correctly handled** and are reclassified as positive controls.

Three concrete improvements were implemented on this branch, each secure-by-default and each with unit tests plus (where applicable) runtime before/after evidence:

| ID | Change | PCI DSS | Status |
|----|--------|---------|--------|
| **A4** | `maskPhoneNumberInLogs` config toggle (default **on**) — phone numbers in server logs reduced to last-4 (e.g. `••••••7890`) | 10.2, 3.x | **Implemented + verified** |
| **A5** | `forceHttpsApiUrl` config toggle (default **on**) — refuse to transmit the OTP over a non-HTTPS gateway URL (loopback `http` allowed for dev) | 4.2.1 | **Implemented + verified** |
| **C2** | FOSS Software Composition Analysis GitHub Action (Trivy) gating on CRITICAL, SARIF + CycloneDX SBOM; `npm` added to Dependabot; `axios` bumped `1.6.2 → 1.18.x` | 6.3.1, 6.3.2 | **Implemented + verified** |

No compliance-blocking defect was found in the SMS authenticator's authentication logic. The most material residual risk is **operational, not code**: the `billpay-poc` realm export carries a live plaintext Twilio credential and runs with `simulation=false` against the real Twilio API — the owner has confirmed this is a dev key to be rotated and moved to the vault (support for which already exists in the code).

---

## 2. Environment & methodology

**Static review:** full read of the SMS authenticator source (authenticator, required actions, code-send helper, gateway client, factory, credential model) and the build/CI/dependency configuration.

**Dynamic validation (safe):** performed against the running `fwc-kc` container, realm `billpay-poc`, with **`simulation` forced ON before every flow** (verified via the admin REST API) so **no live Twilio message was ever sent**. OTPs were read from the container log (the simulation-mode diagnostic). Disposable `sec-test-*@sec.test` users were created and deleted per test. The current-branch jar was built (JDK 17, matching CI) and staged into the container's provider directory; the original release jar and `simulation=false` were restored at the end, leaving the environment exactly as found. The existing `sectest/retest.py` harness was reused for the regression battery.

---

## 3. Implemented fixes

### A4 — Mask phone numbers in logs (PCI 10.2, 3.x)

**Finding.** The phone number (PII) was written unmasked to server logs on the normal send path and in the enrollment required actions:
`ApiSmsService.java` (send success/failure + `cleanPhoneNumber` traces), `PhoneValidationRequiredAction.java:74`, `PhoneNumberRequiredAction.java:212,222`.
(Token/OTP-payload logging was found to be **already mitigated** in the deployed configuration: `hideResponsePayload=true` redacts the response body, `urlencode`+POST means the request body is never captured, and the Basic-auth token rides the `Authorization` header, absent from the logged request line. Residual exposure exists only in gateway profiles not used here — JSON-POST logs the request body on send error; GET-URL mode embeds the token in the URI — see §6.)

**Correction (implemented).** New boolean authenticator-config property **`maskPhoneNumberInLogs`** (label "Mask phone number in logs"), **default `true`**, mirroring the existing `hideResponsePayload` toggle. A shared helper (`PhoneNumberLogMasker.forLog`) renders the number as its last 4 digits (`••••••7890`) when the toggle is on, or the raw value when an operator disables it for debugging. Applied at every phone-logging site. The simulation-mode diagnostic line is intentionally left unmasked — it is a local-dev aid that replaces delivery and is parsed by the test harness; production must run with `simulation=false`.

**Runtime evidence (fwc-kc, enrollment in simulation):**
```
BEFORE (release jar): Validating phone number: +12064567890 of user: sec-test-probe@sec.test
AFTER  (fixed jar):   Validating phone number: ••••••7890 of user: sec-test-probe@sec.test
```

### A5 — Force HTTPS on the SMS gateway URL (PCI 4.2.1)

**Finding.** `ApiSmsService` used the configured `apiurl` with the JDK HTTP client and no scheme check. A misconfigured `http://` gateway URL would transmit the OTP (and credentials) in cleartext over the network.

**Correction (implemented).** New boolean authenticator-config property **`forceHttpsApiUrl`** (label "Force HTTPS on API URLs"), **default `true` (on)** — an admin must intentionally disable it to permit plaintext HTTP. When on, the send is aborted before any request is built unless the URL is `https` (or `http` to a loopback host — `localhost`/`127.0.0.1`/`::1` — for local development). Fails closed: the caller renders the generic "SMS not sent" challenge. The scheme predicate is unit-tested; the URL is never logged in full.

### C2 — FOSS Software Composition Analysis (PCI 6.3.1, 6.3.2)

**Finding.** No dependency-vulnerability (SCA) scanner existed (only OpenGrep SAST for first-party source); the `npm` ecosystem (`app-authenticator-cli`) was not covered by Dependabot/Renovate; no SBOM was produced. `axios ^1.6.2` was materially outdated.

**Correction (implemented).** New workflow `.github/workflows/sca.yml` running **Trivy** (Aqua, Apache-2.0; **not** CodeQL, per constraint). It scans Maven **and** npm dependencies, uploads SARIF to the Security tab plus an artifact, emits a **CycloneDX SBOM** (component inventory, Req 6.3.2), and **gates the build on CRITICAL** while surfacing HIGH/MEDIUM/LOW non-blockingly (so a handed-off pipeline is green on arrival while debt stays visible). `npm` added to `.github/dependabot.yml`. `axios` bumped `^1.6.2 → ^1.16.0` (lockfile regenerated → resolved `1.18.x`).

**Evidence (Trivy `fs`, local run of the same commands):**
- Maven providers (the shipped product): **0 HIGH/CRITICAL**.
- `app-authenticator-cli` before bump: axios carried **1 CRITICAL (form-data, transitive) + 13 HIGH** (SSRF `CVE-2024-39338`, SSRF/credential-leak `CVE-2025-27152`, prototype-pollution, DoS, …).
- After the axios bump: **0 CRITICAL** (gate passes); 2 residual **HIGH** (`lodash`, `tmp`, transitive via `inquirer`) surfaced for triage — see §5.
- SBOM: CycloneDX 1.7, 164 components.

---

## 4. Reclassified as positive controls (not deficiencies)

These were examined closely (some initially suspected) and confirmed correct; they are **defensibility evidence**, not gaps.

- **OTP one-time-use / replay resistance (PCI 8.5.1).** Every code issue overwrites the `code`/`ttl` auth notes in `SmsCodeSender.sendCode()` (`SmsCodeSender.java:82-84`), so any earlier code dies the instant a new one is sent (rotation). A correct entry ends the flow via `context.success()`, which discards the auth session and its notes — there is no reachable replay vector. Verified at runtime: after a resend the pre-resend code is rejected ("old-code-dead").
- **Invalid-attempt limiting (PCI 8.3.4).** Wrong SMS codes are recorded against the realm brute-force protector exactly like failed passwords (`recordBruteForceFailure` → `BruteForceProtector.failedLogin`; gated by `isDisabledByBruteForce` on both login and enrollment). Verified at runtime: repeated wrong codes lock the account (`failureFactor=5`) on both the login and enrollment paths.
- **Resend abuse handling.** The resend ceiling stops issuing codes and emits an audit event (`sms_resend_limit_exceeded`) but deliberately **does not** lock the account — correctly avoiding a denial-of-service vector where resend-spam could lock out a victim. Cooldown + ceiling + refresh-throttling are business-configurable (`resendCooldownSeconds`, `resendMaxCount`) and verified at runtime.
- **Constant-time comparison, `SecureRandom` generation, non-enumerating errors, vault-aware credentials** — all present (`SmsAuthenticator.java:157`, `SmsCodeSender.java:82`, `messages_*.properties`, `SmsServiceFactory.java:42-81`).

---

## 5. Documented recommendations (handoff backlog for the enterprise team)

| ID | Item | PCI DSS | Owner action |
|----|------|---------|--------------|
| **B1** | `billpay-poc` realm export carries a live plaintext Twilio token and runs `simulation=false` against real Twilio. | 8.3.1, 3.x | **Rotate the token** (owner confirms it is a dev key) and switch the realm to `${vault.*}` — **the code already supports this** (`SmsServiceFactory.resolveSecrets`, used by the `payment-qa/uat` + `published-import` variants). Ensure no plaintext secret travels in the handoff export. |
| **C1** | Publish the SBOM with releases. | 6.3.2 | The new SCA workflow already emits a CycloneDX SBOM as a CI artifact; attach it to release assets alongside the cosign signatures. |
| **C2-residual** | 2 transitive **HIGH** in the dev CLI (`lodash` → `CVE-2026-4800`; `tmp` → `CVE-2026-44705`), via `inquirer`. | 6.3.1 | Bump `inquirer` (or add `overrides`) and re-run the SCA workflow; then optionally raise the SCA gate from CRITICAL to HIGH. |
| **C4** | Test coverage remains uneven: `app-authenticator` and `enforce-mfa` have no unit tests. | 6.2.4 | Add coverage as those modules are taken forward. |
| **C5** | No `SECURITY.md` (vuln-disclosure policy), threat model, `CHANGELOG`, or `CODEOWNERS`. | 6.2, 12.x | Add in the receiving repo. |
| **C6** | Both Dependabot and Renovate are configured (possible duplicate PRs). | 6.3.3 | Standardize on one in the receiving repo. |
| **A6** | Factory default `simulation=true`. | operational | Considered low risk (an unconfigured instance cannot send anyway) — left as-is per owner. Ensure production sets `simulation=false` explicitly. |
| **A7** | 6-digit code / 300s TTL (~20 bits). | 8.3 | Acceptable per NIST SP 800-63B given the existing rate-limiting; documented, no change. |

**Note on branch protection / PR gating:** not applicable in this repo — handled by the receiving team's repository governance.

---

## 6. Log-hygiene residuals (other gateway profiles — not the deployed config)

The deployed `billpay-poc` profile (`urlencode`+POST+Basic-auth-header+`hideResponsePayload=true`) does not log the token or OTP. Two other **profiles**, if adopted, would:
- **JSON-POST mode** (`urlencode=false`) logs the request body (containing the OTP) on a send *error* (`ApiSmsService.logErrorStatus/logErrorException`).
- **GET-URL mode** embeds `{apitoken}` in the URI, which appears in the logged request line.
**Recommendation:** have `hideResponsePayload` (or a dedicated flag) also gate request-side logging, or document the safe profile. Low priority given the deployed configuration.

---

## 7. Validation evidence

**Unit tests** (`mvn -pl sms-authenticator -am test`): **27/27 pass** (16 added):
- `PhoneNumberLogMaskerTest` (6) — masking on→last-4, off→raw, non-digits, short numbers, null.
- `ApiSmsServiceSecurityTest` (8) — HTTPS allowed, loopback-http allowed, remote-http/non-http/null rejected, send-over-http refused when force-on, permitted when force-off.
- `SmsAuthenticatorValidationTest` (2) — wrong code → `INVALID_CREDENTIALS` (exercises the constant-time comparator's false branch); correct-but-expired → `EXPIRED_CODE`.

**Runtime regression** (fwc-kc, fixed jar, simulation forced on) via `sectest/retest.py`:

| Test | Result | What it confirms |
|------|--------|------------------|
| D4/F2 malformed phone | PASS | Malformed inputs → no send, form re-prompt |
| P1-8b empty code | PASS | Blank code → re-prompt, no 500, brute-force not incremented |
| F11 login brute-force | PASS | Wrong codes → lockout on the login path |
| F11 enroll brute-force | PASS | Wrong codes → lockout on the enrollment path |
| RESEND | PASS | Cooldown, business-tunable, code rotation (old code dead), ceiling, newest-code sign-in, resends don't touch brute-force |
| P1-8a missing config | PASS | Missing `length`/`ttl` → guarded error, no unhandled NPE |
| N8 region | PASS* | *Failed on `billpay-poc` because it has no `allowedRegions`; **passed** once `allowedRegions=US` was applied — a realm-config artifact, not a code regression (region code untouched). |

The fixed jar loaded with no startup errors and completed a full enrollment (choice → phone → SMS → onboarding). Environment restored to original (release jar, `simulation=false`, `apiurl` untouched, no leftover users).

---

## 8. PCI DSS 4.0.1 requirement mapping

| Requirement | Coverage in this codebase |
|-------------|---------------------------|
| **4.2.1** strong cryptography in transit | **A5** force-HTTPS toggle (default on) on the gateway URL. |
| **8.3.1** auth factors unreadable | OTP held only in a short-lived server-side auth-session note; gateway credentials vault-capable (B1). |
| **8.3.4** limit invalid auth attempts | Realm brute-force lockout on wrong SMS codes (login + enrollment), verified. |
| **8.4 / 8.5.1** MFA, no replay/bypass | SMS second factor; OTP one-time-use via rotation + session teardown, verified. |
| **10.2 / 3.x** no sensitive data in logs | **A4** phone masking (default on); token/OTP already redacted in the deployed profile. |
| **6.2.4** secure coding assurance | Constant-time compare + expiry now unit-tested; 27 tests green. |
| **6.3.1** identify vulnerabilities | **C2** Trivy SCA gate + Dependabot npm coverage; `axios` remediated. |
| **6.3.2** component inventory | **C2** CycloneDX SBOM produced in CI. |

---

*Prepared for handover. Implemented changes live on branch `security/sms-pci-hardening`; see the commit for the diff and tests.*

---

## 9. Follow-up hardening pass (2026-07-10) — enrolment path & gateway client

A second, narrower pass focused on the parts of the **deployed** `sms-authenticator` module the first
audit covered only lightly: phone-number **enrolment/validation** and the **gateway HTTP client**.
(Email OTP and the app-push authenticator were explicitly ruled **out of scope** by the owner — email is
the distinct password-reset factor so email-OTP-as-2FA is not used, and app-push is not deployed.) Three
concrete fixes, each with unit tests plus runtime before/after evidence in a Keycloak `26.6.3` container
(realm `sectest`, `sms-2fa` config, `simulation` on; disposable container torn down afterward). Suite is
now **39/39 green** (12 added).

| ID | Change | Severity | Status |
|----|--------|----------|--------|
| **F1** | `allowedRegions` / `numberTypeFilters` allowlist enforced **fail-closed** at enrolment, independent of the `normalizePhoneNumber` / `forceRetryOnBadFormat` formatting toggles | **HIGH** (SMS toll-fraud / pumping) | **Implemented + verified** |
| **F2** | Connect + request **timeouts** on the SMS gateway `HttpClient`/`HttpRequest` | Medium (auth-thread DoS) | **Implemented + verified** |
| **F3** | Null-guard a missing `mobile_number` form field (was an unhandled NPE/500) | Low (robustness) | **Implemented + verified** |

### F1 — Region/type allowlist was silently bypassed (PCI 8.x anti-abuse; toll-fraud)

**Finding.** The region allowlist (`allowedRegions`), `isValidNumber`, and number-type filters lived inside
`PhoneNumberRequiredAction.formatPhoneNumber`, which ran only when `normalizePhoneNumber=true` **and** only
rejected when `forceRetryOnBadFormat=true` — both default **false**. In every other configuration a number
whose region was not in the allowlist was stored and texted anyway (the `formatPhoneNumber==null` "reject"
signal fell through). Enrolment is where the user chooses the destination number, so a configured allowlist
gave **zero** protection in the default config — an SMS-pumping / toll-fraud primitive. Independently
reported in `app-authenticator/SMS-REGION-ALLOWLIST-BYPASS.md` (now marked resolved).

**Correction (implemented).** Refactored the region/type/validity logic into a shared
`parseAndValidatePhoneNumber` + boolean `validateRegionAndType`, and added a standalone **fail-closed gate**
in `processAction`: when `allowedRegions` or `numberTypeFilters` is configured, a number that is
out-of-region, wrong-type, invalid, or unparseable is rejected (re-prompt) **regardless** of the two
formatting toggles. The formatting path is otherwise unchanged, so existing best-effort-normalisation
configs behave as before. Config help text corrected to drop the "only applied when Format phone number is
enabled" caveat.

**Runtime evidence (container, default config `normalizePhoneNumber=false`/`forceRetryOnBadFormat=false`,
`allowedRegions=US`):**
```
BEFORE (pre-fix jar): enrol +447400123456 → ACCEPTED; log: "***** SIMULATION MODE ***** Would send SMS to +447400123456 ..."
AFTER  (fixed jar):   enrol +447400123456 → REJECTED; log: "region GB is not in the allowed regions [US]" + "Rejected phone-number enrolment ..." (NO send)
AFTER  (fixed jar):   enrol +12015550123  → ACCEPTED; log: "Would send SMS to +12015550123 ..." (in-region still works)
```
Unit test `PhoneNumberRegionEnforcementTest` drives the full flag matrix (out-of-region rejected in all
three combinations, in-region accepted, unparseable rejected, number-type filter enforced, no-allowlist
backward-compat).

### F2 — No timeout on the SMS gateway HTTP client (auth-thread DoS)

**Finding.** `ApiSmsService` created `HttpClient.newHttpClient()` and built requests with no connect/request
timeout, then blocked on `client.send(...)` on the Keycloak auth thread. A hung/slow/black-holed gateway
could pin that worker indefinitely (thread-pool exhaustion → Keycloak-wide DoS).

**Correction (implemented).** `connectTimeout(5s)` on the client and `timeout(10s)` on every request; a
timeout surfaces through the existing `catch` → generic "SMS not sent" (fail closed). **Runtime:** with the
gateway pointed at a non-routable address (`192.0.2.1`, RFC 5737) and `simulation=false`, the send now fails
in **~5s** (`Failed to send message ... Validate your config.`) instead of hanging. Unit tests assert each
built request carries the timeout.

### F3 — NPE on a missing `mobile_number` field

**Finding.** `processAction` dereferenced `getFirst("mobile_number")` in a regex matcher; a malformed POST
omitting the field threw NPE → 500. **Correction:** null/blank-guard and re-prompt (mirrors the login-path
empty-OTP guard). Unit-tested.

### Documented, not implemented (owner decision)
- **Cross-session SMS send cap** — the resend cooldown/ceiling is per-auth-session, so fresh sessions can
  re-trigger sends. Deferred: the owner mitigates this at the perimeter with **reCAPTCHA on the flow + rate
  limiting at the API gateway**. Left as a possible later provider-side follow-up.
- **`getJsonBody` unescaped JSON concatenation** (`ApiSmsService`) — not reachable in the deployed
  `urlencode` profile (numbers are sanitised to `[0-9+]`); recommend a JSON writer if the JSON-POST profile
  is ever adopted.
- **`release.yml`** — add a `cosign-release` version pin and gate the release on the SAST/SCA suite.
