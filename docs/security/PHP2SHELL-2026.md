# PHP runtime security diagnostic — October 2026

This is a version-threshold diagnostic, **not** a vulnerability exploit detector or PHP interpreter patch.
The reported PHP2Shell identifiers and thresholds must be independently checked against official
PHP release notes and vulnerability advisories before this document is published as an authoritative advisory.

## Upstream version thresholds to verify

| PHP branch | Minimum upstream fixed version |
| --- | --- |
| 8.2 | 8.2.35 |
| 8.3 | 8.3.36 |
| 8.4 | 8.4.27 |
| 8.5 | 8.5.12 |

PHP 7.4, 8.0, and 8.1 are treated as unsupported upstream branches, not proven exploitable.
Distributor-maintained packages may have backported fixes without an upstream version bump.
Use `--vendor-build` to report `UNKNOWN` until the vendor security bulletin and package revision are checked.

## Examples

    php bin/loguard-runtime-security-check
    php bin/loguard-runtime-security-check --format=json
    php bin/loguard-runtime-security-check --version=8.4.26 --strict
    php bin/loguard-runtime-security-check --version=8.4.26 --vendor-build

Normal invocation is read-only and exits successfully; strict mode exits 1 for an upstream
version below the configured threshold. Unknown and unsupported statuses do not block execution.

## Remediation

1. Identify PHP versions separately for CLI and active PHP-FPM/web processes.
2. Verify applicable official PHP and distribution security advisories.
3. Upgrade or apply confirmed vendor security updates through change control.
4. Restart PHP-FPM workers and confirm the active runtime version.
5. Check application health and security monitoring after the update.

Cloudflare WAF can provide defense in depth but does not replace interpreter patching.
The LoGuard SDK cannot remediate interpreter vulnerabilities, and this tool performs no
network requests, telemetry, runtime blocking, or automatic updates.


## Verified security references

The CVE identifiers and upstream fixed-version thresholds were
cross-checked against the following October 21, 2026 publications:

- PHP 8.5.12 official release announcement:
  https://news-web.php.net/php.announce/513
- Canadian Centre for Cyber Security:
  https://www.cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-impacting-php-cve-2026-109618-cve-2026-109619
- PHP upstream advisory:
  https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp

PHP 8.1 and older branches may also be affected despite being
classified as UNSUPPORTED by this diagnostic. Upgrade or obtain
a vendor-confirmed security backport.
