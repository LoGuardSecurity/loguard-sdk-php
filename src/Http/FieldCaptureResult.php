<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Http;

/**
 * Result of FieldPolicy::captureBody(). Never thrown as an exception —
 * a malformed/oversized/wrong-type request body must never break the
 * request it's attached to; the outcome is reported through these flags
 * instead, so a caller (or a future "Integration Coverage" panel) can
 * tell "no data" apart from "data rejected, and why".
 */
final class FieldCaptureResult
{
    /** @param array<string, mixed> $fields */
    public function __construct(
        public readonly array $fields = [],
        public readonly bool $parseError = false,
        public readonly bool $tooLarge = false,
        public readonly bool $unsupportedContentType = false,
        public readonly bool $depthExceeded = false,
    ) {
    }

    public static function empty(): self
    {
        return new self();
    }

    /** @return array<string, mixed> merge into an event's meta */
    public function toMeta(): array
    {
        $meta = [];
        if ($this->fields !== []) {
            $meta['body'] = $this->fields;
        }
        if ($this->parseError) {
            $meta['body_parse_error'] = true;
        }
        if ($this->tooLarge) {
            $meta['body_too_large'] = true;
        }
        if ($this->unsupportedContentType) {
            $meta['body_unsupported_content_type'] = true;
        }
        if ($this->depthExceeded) {
            $meta['body_depth_exceeded'] = true;
        }

        return $meta;
    }
}
