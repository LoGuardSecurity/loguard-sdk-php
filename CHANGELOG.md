# Changelog

## 1.0.1 - 2026-09-23

- Fixed autoload resolution for the spool worker when the SDK is installed as a Composer dependency.
- Added a package-install regression test for the Composer binary.

## 1.0.0 - 2026-09-23

- Added injectable transport and event sink contracts.
- Added global metadata sanitization and event/request size limits.
- Added a durable, bounded filesystem spool and one-shot worker.
- Added framework-neutral HTTP request context, capture policy and event factory.
- Added PSR-15 and CodeIgniter 3 adapters; reduced Laravel middleware to an adapter.
- Hardened URL validation, retry/timeout bounds, redirect handling and response parsing.
- Made asynchronous capture fail-open for every throwable.
- Added PHP 8.1–8.5 CI coverage and tests for the new boundaries.

The default timeout is now 3 seconds and the default send attempt count is 2.
Applications that need the previous behavior can configure both values explicitly.
