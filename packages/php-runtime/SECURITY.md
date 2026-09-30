# Security Policy

LoGuard PHP Runtime handles security telemetry inside customer applications, so security and data minimization are part of the package design.

## Supported versions

Until a stable `1.x` release is available, security fixes are provided for the latest published `0.x` release.

Production deployments should stay on the latest compatible version.

## Reporting a vulnerability

Please do not publish suspected vulnerabilities in a public GitHub issue.

When reporting a security problem, include enough information to reproduce and understand the issue:

- affected LoGuard Runtime version
- PHP version
- framework and framework version
- deployment environment
- reproduction steps
- expected behavior
- observed behavior
- security impact

Do not include production API keys, passwords, session values, private keys, customer data or other secrets.

A private security contact will be documented with the public repository before the first release.

## Security model

The Runtime is designed with the following boundaries:

- application requests do not send network traffic to LoGuard
- delivery credentials belong to the background worker
- telemetry processing is fail-open
- sensitive fields are filtered before local spooling
- local spool files use restrictive permissions
- HTTPS is required by default
- delivery requests are signed with HMAC-SHA256
- request signing covers the exact serialized request body
- redirects are not followed by the delivery transport
- forwarded client IP data is trusted only through configured proxies
- capture limits bound field count, value size, request body size and nesting depth

These controls reduce the risk of telemetry collection but do not replace application-specific security review.
