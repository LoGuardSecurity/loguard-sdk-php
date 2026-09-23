<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Privacy;

use LoGuard\Sdk\Http\FieldPolicy;

final class Sanitizer
{
    public function __construct(
        private readonly int $maxDepth = 8,
        private readonly int $maxItems = 100,
        private readonly int $maxStringBytes = 4096
    ) {
    }

    /**
     * @param array<string, mixed> $meta
     * @return array<string, mixed>
     */
    public function meta(array $meta): array
    {
        $clean = $this->value($meta, 0);

        return is_array($clean) ? $clean : [];
    }

    private function value(mixed $value, int $depth): mixed
    {
        if ($depth >= $this->maxDepth) {
            return '[truncated]';
        }
        if (is_string($value)) {
            return strlen($value) <= $this->maxStringBytes
                ? $value
                : substr($value, 0, $this->maxStringBytes);
        }
        if (is_float($value) && !is_finite($value)) {
            return null;
        }
        if (is_int($value) || is_float($value) || is_bool($value) || $value === null) {
            return $value;
        }
        if (!is_array($value)) {
            return '[unsupported]';
        }

        $out = [];
        $count = 0;
        foreach ($value as $key => $item) {
            if ($count++ >= $this->maxItems) {
                break;
            }
            if (is_string($key) && FieldPolicy::isForbiddenFieldName($key)) {
                continue;
            }
            $out[$key] = $this->value($item, $depth + 1);
        }

        return $out;
    }
}
