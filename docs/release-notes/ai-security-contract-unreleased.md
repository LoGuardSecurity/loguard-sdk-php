# AI telemetry and error privacy — unreleased

## Changes

- Transport errors no longer include arbitrary HTTP response bodies or `detail` values in their messages. HTTP status classification and SDK exception types are retained. Network failures use bounded generic messages instead of underlying connection text.
- Added AI-event wire/signature and error-privacy regression tests, integration guidance and a dedicated CI workflow. Tests use synthetic data with mocks or loopback endpoints.

## Migration

If application code parses exception text or expects response/plan details there, switch to the SDK's exception types and application-owned error context. Never log credentials or full event objects. Manual AI telemetry uses the existing Event API; this release does not add automatic LLM capture.

### PHP AI delivery: migration required

- AI metadata is validated separately from the HTTP/web sanitizer. Oversize/invalid content is rejected, not silently truncated. Prompt, response and tool-result fields accept at most 8000 UTF-8 bytes; this byte limit is deliberately more conservative than the server's character limit.
- Empty PHP `tool_args=[]` encodes as the JSON object `{}`. Unknown/internal metadata and system/developer content are excluded by the AI policy.
- `eventAsync()` does not enqueue AI events and returns without delivery, following its existing never-throws interface. Use explicit `event()` / `eventBatch()` with bounded timeouts and an appropriate application failure-handling strategy. Do not assume existing asynchronous AI calls will continue to deliver.
- Full/runtime FileSpool refuses AI content; the Laravel delivery job rejects AI input at construction. This does not remove content already stored by an application or prevent application-managed persistence.
- PHP Runtime's AI policy remains syntax-compatible with PHP 7.4; the full SDK still requires PHP 8.1+. Supported-version CI results must be checked before release.

## Validation and release scope

The existing offline/unit/loopback suites and added regressions passed on the maintainer's Mac before this documentation-only finalization. CI actions are pinned to commit SHA; the multi-version CI matrix has not yet run for this branch.

These changes do not establish production end-to-end delivery or detector accuracy. SDK → ingest → temporary cache → detector → finding, notification isolation and persistent-storage checks remain separate release gates. Server processing remains off during preparation.

Package versions and tags are intentionally unchanged. Choose the release version after reviewing compatibility impact and CI results. No registry publication is performed by the workflow.
