# Security model

LoGuard signs each request with HMAC-SHA256 over the timestamp and the exact
JSON bytes sent to the API. TLS certificate and hostname verification are
always enabled. Redirects are rejected so credentials cannot be replayed to a
different host.

## Data collection

HTTP adapters collect only the response status, method, path and resolved
client address by default. Headers, query parameters and JSON fields require an
explicit allowlist. Authorization data, cookies, session identifiers,
passwords, tokens, private keys and common payment secrets are denied in every
capture path, including manually supplied event metadata.

Field-name filtering cannot detect a secret pasted into a harmless free-text
field. Keep free-text fields out of capture allowlists.

Forwarded addresses are accepted only when the direct peer is trusted. The
resolver walks the proxy chain from right to left and returns the first
untrusted address. Configure only proxies you operate.

## Resource limits

Configuration bounds network timeouts and retry attempts. Responses, request
bodies, JSON depth, metadata depth, collection length, string length and final
event size are all limited. These limits protect application workers from a
slow or malicious endpoint and from unexpectedly large application data.

## Failure isolation

Synchronous APIs throw typed exceptions. Automatic HTTP capture and
`eventAsync()` catch all failures and never replace the application's response.
For durable production delivery use a framework queue or `FileSpool`; a
shutdown callback is only a compatibility fallback and still runs in the PHP
worker.

## Credentials

Load API keys from the environment or a secret manager. Never write them to a
repository, URL, event metadata or exception message. Use HTTPS in production.
`allowInsecureTransport` exists only for isolated local development.

Please report vulnerabilities privately through the security contact listed on
the LoGuard website. Do not include live API keys or customer payloads.
