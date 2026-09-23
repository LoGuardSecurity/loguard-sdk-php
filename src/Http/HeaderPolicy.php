<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Http;

/**
 * Shared header-tracking policy for HTTP middleware.
 *
 * Mirrors loguard/integrations/fastapi.py KNOWN_EXPLOIT_HEADERS /
 * _FORBIDDEN_TRACK_HEADERS: request headers are NEVER forwarded to
 * LoGuard by default. An application can opt in to sending specific
 * header names for the exploit-pattern detectors, but a fixed
 * deny-list of headers that can carry credentials is enforced in code
 * — not just documented — so a misconfiguration can never leak
 * secrets to LoGuard.
 */
final class HeaderPolicy
{
    /**
     * Header names that have historically carried real-world RCE
     * payloads. A starting point for track_headers, not a guarantee
     * of completeness.
     */
    public const KNOWN_EXPLOIT_HEADERS = [
        'user-agent',
        'referer',
        'x-beresource',
        'x-anonresource-backend',
    ];

    /**
     * Never forwarded, even if explicitly requested via track_headers.
     */
    public const FORBIDDEN_HEADERS = [
        'authorization',
        'cookie',
        'set-cookie',
        'x-api-key',
        'x-auth-token',
        'proxy-authorization',
    ];

    public const MAX_HEADER_VALUE_LENGTH = 512;

    /**
     * @param string[] $requested
     * @return string[] Normalized (lowercased), with forbidden entries removed.
     */
    public static function sanitizeRequested(array $requested): array
    {
        $normalized = array_unique(array_map(
            'strtolower',
            array_values(array_filter($requested, 'is_string'))
        ));

        return array_values(array_diff($normalized, self::FORBIDDEN_HEADERS));
    }

    /**
     * @param string[] $trackHeaders Already-sanitized (see sanitizeRequested()) lowercased header names.
     * @param callable(string):?string $getHeader Reads one header value by lowercase name, or null if absent.
     * @return array<string, string>
     */
    public static function collect(array $trackHeaders, callable $getHeader): array
    {
        if (empty($trackHeaders)) {
            return [];
        }

        $collected = [];
        foreach ($trackHeaders as $name) {
            $value = $getHeader($name);
            if ($value !== null) {
                $collected[$name] = mb_substr($value, 0, self::MAX_HEADER_VALUE_LENGTH);
            }
        }

        return $collected;
    }
}
