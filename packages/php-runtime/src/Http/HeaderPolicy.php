<?php

declare(strict_types=1);

namespace LoGuard\Runtime\Http;

final class HeaderPolicy
{
    public const KNOWN_EXPLOIT_HEADERS = array(
        'user-agent',
        'referer',
        'x-beresource',
        'x-anonresource-backend',
    );

    public const FORBIDDEN_HEADERS = array(
        'authorization',
        'cookie',
        'set-cookie',
        'x-api-key',
        'x-auth-token',
        'proxy-authorization',
    );

    public const MAX_HEADER_VALUE_LENGTH = 512;

    /**
     * @param array<mixed> $requested
     * @return array<string>
     */
    public static function sanitizeRequested(array $requested): array
    {
        $normalized = array();

        foreach ($requested as $name) {
            if (!is_string($name)) {
                continue;
            }

            $name = strtolower($name);

            if (in_array($name, self::FORBIDDEN_HEADERS, true)) {
                continue;
            }

            $normalized[$name] = true;
        }

        return array_keys($normalized);
    }

    /**
     * @param array<string> $trackHeaders
     * @param callable $getHeader
     * @return array<string, string>
     */
    public static function collect(
        array $trackHeaders,
        callable $getHeader
    ): array {
        if ($trackHeaders === array()) {
            return array();
        }

        $collected = array();

        foreach ($trackHeaders as $name) {
            $value = $getHeader($name);

            if ($value === null) {
                continue;
            }

            $collected[$name] = self::cut(
                $value,
                self::MAX_HEADER_VALUE_LENGTH
            );
        }

        return $collected;
    }

    private static function cut(
        string $value,
        int $maxLength
    ): string {
        if (function_exists('mb_substr')) {
            return mb_substr(
                $value,
                0,
                $maxLength,
                'UTF-8'
            );
        }

        return substr($value, 0, $maxLength);
    }
}
