# AI telemetry contract

AI telemetry is explicit: an HTTP middleware cannot infer LLM prompts, responses or tool calls. Use the existing manual Event API with `ai_llm_request`, `ai_llm_response` or `ai_tool_call`. Set the ingest base URL to `https://api.loguard.org` explicitly. Never embed a real key in examples, fixtures or logs.

Required metadata is `prompt` for requests, `response` for responses, and `tool_name` plus an object/string `tool_args` for tool calls. An empty JSON object is valid for `tool_args`. Use synthetic data for integration tests. Exclude system/developer messages and secrets before invoking an SDK. For SDKs other than PHP the generic API preserves caller metadata; it is not a privacy filter.

The server remains authoritative for project membership, billing entitlement, signed ingestion, consent and rollout. A successful HTTP response or settings save does not prove delivery to a detector. Processing is asynchronous and observation-only; it does not authorize tools or stop model execution.

## Error privacy

Transport exception classes and HTTP status mapping are preserved. Error text no longer includes arbitrary response bodies, detail fields, plan values or underlying connection messages. Match exception types rather than parsing strings. Do not log event objects, request bodies, credentials or model content when handling errors. This is not a guarantee against logging performed by application code or HTTP instrumentation.

## Content delivery

Do not persist AI content in job queues, file spools, debug traces or retry archives. Server-side temporary content retention does not cover copies made by an application or SDK integration. SDK queues do not acquire an automatic five-minute TTL from the server cache.

The PHP SDK now validates AI metadata separately from its web sanitizer. It rejects oversize/invalid content rather than truncating it, preserves request/response/tool-result strings up to 8000 UTF-8 bytes, removes system/developer content and unknown fields, and maps empty PHP `tool_args=[]` to JSON `{}`. Byte limits are deliberately more conservative than the server's Unicode-character limits.

PHP `eventAsync()` does not enqueue AI events and returns without delivery. Use explicit `event()` or `eventBatch()` with bounded timeouts; handle failures outside the LLM application's critical path where appropriate. FileSpool rejects AI events; Laravel SendLoGuardEvents rejects them at construction. These changes do not remove previously persisted content. The supported paths cannot prevent an application from manually serializing sensitive data elsewhere.

## Validation scope

AI contract tests use synthetic credentials and mocks or loopback servers only. Run the normal repository unit tests as well. They do not establish production end-to-end readiness, detector accuracy or zero false positives. Before releasing, document the changed error-text behavior in the release notes and perform a limited project canary without external notifications.
