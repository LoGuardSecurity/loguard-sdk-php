<?php

declare(strict_types=1);

namespace LoGuard\Runtime\Http;

final class FieldCaptureResult
{
    /** @var array<string, mixed> */
    public $fields;

    /** @var bool */
    public $parseError;

    /** @var bool */
    public $tooLarge;

    /** @var bool */
    public $unsupportedContentType;

    /** @var bool */
    public $depthExceeded;

    public function __construct(
        array $fields = array(),
        bool $parseError = false,
        bool $tooLarge = false,
        bool $unsupportedContentType = false,
        bool $depthExceeded = false
    ) {
        $this->fields = $fields;
        $this->parseError = $parseError;
        $this->tooLarge = $tooLarge;
        $this->unsupportedContentType = $unsupportedContentType;
        $this->depthExceeded = $depthExceeded;
    }

    public static function empty(): self
    {
        return new self();
    }

    /** @return array<string, mixed> */
    public function toMeta(): array
    {
        $meta = array();

        if ($this->fields !== array()) {
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
