# LoGuard PHP SDK — Security Notes

This is not a claim of "no vulnerabilities" — no client library can
honestly claim that. It's a record of the attack classes considered
during design/review, what's mitigated and how, what's explicitly
out of scope for a client SDK, and what a consumer of this package
is still responsible for.

## Threat classes reviewed

| Class | Status | Notes |
|---|---|---|
| SSRF via `base_url` | Mitigated at the config layer, not eliminated | `base_url` is developer-supplied config, not attacker input, in every normal deployment. `Config` enforces `https://` by default. `Transport` restricts curl to `http`/`https` schemes only (`CURLOPT_PROTOCOLS`), so even a misconfigured `base_url` can't reach `file://`, `gopher://`, etc. If your app lets *end users* influence `base_url` at runtime, that's an application-level SSRF risk no SDK config can fix — don't do that. |
| Unsafe redirects / credential leak via redirect | Mitigated | `CURLOPT_FOLLOWLOCATION => false`, `CURLOPT_MAXREDIRS => 0`. A 3xx from the ingest endpoint is never auto-followed, so a compromised or misconfigured LoGuard endpoint can't redirect the signed request (carrying your API key) to an attacker-controlled host. Verified in `TransportIntegrationTest::testRedirectIsNeverFollowed`. |
| TLS verification / certificate validation | Enforced, not configurable off | `CURLOPT_SSL_VERIFYPEER => true`, `CURLOPT_SSL_VERIFYHOST => 2`, hardcoded. There is no SDK option to disable this. `allowInsecureTransport` only permits a plain-`http://` `base_url` for local development; it does not touch TLS verification (irrelevant for `http://` anyway, since there's no TLS to verify). |
| API key / secret leakage in logs | Mitigated | The SDK never logs headers or request bodies. `LoGuardAuthException` messages are static strings ("Invalid API key") that never interpolate the key itself. Applications are responsible for not logging their own `$loguard->event()` call sites with secrets in `meta`. |
| Sensitive data leakage via forwarded headers | Mitigated in code, not just docs | `HeaderPolicy::FORBIDDEN_HEADERS` (`authorization`, `cookie`, `set-cookie`, `x-api-key`, `x-auth-token`, `proxy-authorization`) is stripped from any `track_headers` list even if explicitly requested — see `HeaderPolicyTest::testForbiddenHeadersAreAlwaysStrippedEvenIfRequested`. |
| Sensitive data leakage via query/body capture (`track_query_params` / `track_body_json_paths`) | Mitigated for field-name-based secrets; explicitly NOT content scanning | Off by default, opt-in per named route. `FieldPolicy::FORBIDDEN_FIELD_PATTERNS` strips any field whose *name* matches a secret pattern, even if explicitly allowlisted, at any nesting depth. Only `application/json` bodies are parsed; multipart/form-data, files, and any other content type are rejected outright before parsing. Oversized (`max_body_bytes`) and over-deep (`max_body_json_depth`) bodies are rejected before parsing, not partially processed. **Not mitigated, and not claimed to be**: a secret pasted into an otherwise innocuously-named field's free-text value (e.g. a token inside a `comment` field) is not detected — this is name-based redaction, not content scanning, and must be described to consumers as such. |
| IP spoofing via `X-Forwarded-For` | Mitigated, secure by default | `ClientIp::resolve()` only trusts `X-Forwarded-For` when the *direct* TCP peer is in an explicitly configured trust list (IP or CIDR). Empty config (the default) means the header is never trusted. See `ClientIpTest`. |
| Header injection (CRLF injection into outbound request headers) | Mitigated | Header values passed to curl come from `Signing::sign()` (SDK-controlled: timestamp, HMAC hex digest, UUID) or from `HeaderPolicy::collect()`, which truncates but does not currently strip control characters from forwarded header *values* being sent to LoGuard as **data in the JSON body** (`meta.headers`), not as outbound HTTP headers themselves — so there is no CRLF-into-a-real-header vector here; forwarded header values end up as JSON string values, which `json_encode` escapes safely. |
| Request smuggling-related behavior | Not directly applicable | This SDK is an HTTP *client*, not a proxy or server; it does not parse or forward raw HTTP framing from untrusted input. The one place request data flows through is `meta.headers`, and that's JSON-serialized, not re-emitted as HTTP framing. |
| Unsafe (de)serialization | Mitigated | Only `json_encode`/`json_decode` are used (`JSON_THROW_ON_ERROR` on encode). No `unserialize()`, no `eval`, no dynamic class instantiation from server responses anywhere in the SDK. |
| Path traversal | Not applicable | The SDK does not read/write files based on any request or response content. `register_shutdown_function`-based flushing only touches in-memory state. |
| Command execution / code injection / template injection | Not applicable | No `exec`/`shell_exec`/`eval`/template engine anywhere in `src/`. (The test-only `MockServerProcess` does call `proc_open`, but only in `tests/`, only with a hardcoded, non-interpolated-from-external-input command, and is not shipped in the package — excluded from `autoload`, not part of `composer` production installs.) |
| Insecure defaults | Reviewed | HTTPS required by default; TLS verification always on; redirects never followed; sensitive headers never forwarded; `X-Forwarded-For` never trusted by default; retries bounded (default 3); response size capped (5 MiB). |
| Dependency vulnerabilities | Minimized by having ~zero dependencies | Core package requires only `ext-curl`, `ext-json`, `ext-mbstring` — all PHP core extensions, not Composer packages. `dev` dependencies (PHPUnit, Testbench, PHPStan) never ship to production installs (`composer install --no-dev`). Run `composer audit` in CI regardless — that's a supply-chain check this document can't do for you. |
| Malicious/malformed server responses | Mitigated | `Transport::raiseForStatus()` treats a JSON-decode failure as `null` rather than throwing/crashing (`TransportIntegrationTest::testMalformedJsonResponseDoesNotCrashTheClient`). All array reads use `??` defaults. |
| Oversized responses / memory exhaustion | Mitigated | Curl write callback aborts the transfer once `Transport::MAX_RESPONSE_BYTES` (5 MiB) is exceeded, rather than buffering an attacker-controlled amount of data (`testOversizedResponseIsAbortedNotBuffered`). |
| Oversized events / queue exhaustion | Mitigated | Event `path` is truncated to 1024 chars, `type`/`ip`/`service` to 64, `userId` to 128, header values collected by middleware to 512 — matching the other SDKs' limits exactly. The in-memory `eventAsync()` buffer is capped at 2000 events (`Client::$maxQueueSize`); once full, the oldest queued event is dropped (with an optional `onDropped` callback) rather than growing unbounded. |
| Retry storms | Mitigated | Retries are bounded (`retries`, default 3) with linear backoff: `0.4s * attempt`. No unbounded/exponential-without-cap retry loop exists anywhere in the SDK. |
| Resource exhaustion (threads/connections) | Not applicable in the same way as long-running runtimes | PHP's typical request-per-process model means there's no persistent connection pool or thread pool to exhaust inside the SDK itself; each `Transport::execute()` call opens and closes one curl handle. If you use `eventAsync()` heavily, the bound is the 2000-event in-memory queue, not open connections. |
| Race conditions / concurrency issues | Largely not applicable | Standard PHP-FPM/CLI execution is single-threaded per request; `Client` is not designed to be shared across true OS threads (PHP userland is not multi-threaded by default). If you run under a threaded SAPI (e.g. certain Swoole/pthreads setups), construct one `Client` per worker/coroutine rather than sharing one across concurrent contexts — this is documented, not solved by an internal lock, since adding locking for a scenario most PHP deployments never hit would be unjustified complexity. |
| Improper error handling / information disclosure | Mitigated | Exceptions carry short, server-controlled-but-truncated (`400` chars) snippets for debugging, never full response bodies or secrets. Application code decides what (if anything) to expose to end users. |

## What this SDK does **not** try to solve

- **Application-level authorization** — the SDK reports events, it
  does not enforce access control. Don't rely on LoGuard event
  reporting itself as a security control; it's observability, not
  a WAF layer, for the pieces implemented here (the deprecated
  Ed25519 "Shield" sentinel-verdict feature present in some sibling
  SDKs was intentionally **not** ported — see the parity notes in
  the top-level engineering summary).
- **Multi-tenant secret isolation** — if multiple tenants share a PHP
  process (unusual, but possible with some worker architectures),
  make sure each tenant's `Client` is constructed with that tenant's
  own `Config`; the SDK has no tenant concept of its own.
- **Supply-chain integrity of Composer/PHP itself** — run `composer
  audit`, pin versions, and use Composer's lock file in CI; this is
  standard PHP hygiene outside this SDK's scope.

## Reporting a vulnerability

Please report suspected vulnerabilities in this SDK privately rather
than as a public GitHub issue — see `SECURITY.md` in the main LoGuard
backend repository for the current disclosure process and contact.
