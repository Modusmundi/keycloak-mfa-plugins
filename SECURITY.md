# Security Policy

## Supported versions

Only the latest release receives security fixes.

## Reporting a vulnerability

Please do not open a public issue for security problems. Report them privately via
[GitHub security advisories](../../security/advisories/new) for this repository.

## Security reviews

A recorded audit of the SMS authenticator (July 2026, PCI DSS 4.0.1 focus) is in
[SECURITY-AUDIT.md](SECURITY-AUDIT.md). A resolved high-severity enrolment finding is documented in
[sms-authenticator/SMS-REGION-ALLOWLIST-BYPASS.md](sms-authenticator/SMS-REGION-ALLOWLIST-BYPASS.md).

CI runs a SAST scan (OpenGrep) and an SCA scan with SBOM generation (Trivy, CycloneDX) on every push to
`main` and on pull requests; the SCA gate fails the build on CRITICAL findings.
