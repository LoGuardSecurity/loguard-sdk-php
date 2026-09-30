# Changelog

This file records user-visible changes to LoGuard PHP Runtime.

## 0.1.0 - 2026-09-30

First public release.

### Added

- PHP 7.4+ Runtime package
- Laravel Composer package discovery
- automatic Laravel middleware registration
- automatic security telemetry capture
- query parameter capture
- JSON and vendor JSON body capture
- form-urlencoded body capture
- local sensitive-field filtering
- sensitive header exclusion
- trusted-proxy-aware client IP handling
- authenticated Laravel user identification
- bounded event and body processing
- fail-open request middleware
- local file spool
- restrictive spool filesystem permissions
- background delivery worker
- HMAC-SHA256 request signing
- HTTPS verification
- retry handling for transient ingest failures
- Laravel `.env` loading in the worker
- automatic Laravel `storage/loguard-spool` detection
- Composer `vendor/bin/loguard-runtime-worker` command

### Security

- web requests do not perform LoGuard network delivery
- API credentials remain in the worker environment
- Authorization and Cookie headers are excluded
- multipart and binary bodies are not automatically captured
- forwarding headers are trusted only through configured proxies
