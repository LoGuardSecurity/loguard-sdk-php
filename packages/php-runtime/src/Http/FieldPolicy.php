<?php

declare(strict_types=1);

namespace LoGuard\Runtime\Http;

final class FieldPolicy
{
    public const FORBIDDEN_FIELD_PATTERNS = array(
        'password', 'passwd', 'pwd', 'secret', 'token',
        'access_token', 'refresh_token',
        'api_key', 'apikey', 'authorization', 'cookie',
        'session', 'csrf', 'xsrf',
        'private_key', 'client_secret', 'ssn',
        'card_number', 'card_num', 'cvv', 'cvc',
        'credit_card', 'pin', 'otp',
        'auth_token', 'authentication_token',
        'auth_secret', 'auth_password',
    );

    public const DEFAULT_MAX_BODY_BYTES = 32 * 1024;
    public const DEFAULT_MAX_JSON_DEPTH = 8;

    public const DEFAULT_MAX_QUERY_PARAMS = 64;
    public const DEFAULT_MAX_QUERY_VALUE_BYTES = 4096;
    public const DEFAULT_MAX_QUERY_DEPTH = 4;

    /**
     * Automatic bounded security-oriented query capture.
     *
     * @param array<mixed> $queryParams
     * @return array<string, mixed>
     */
    public static function captureSecurityQuery(
        array $queryParams,
        int $maxParams = self::DEFAULT_MAX_QUERY_PARAMS,
        int $maxValueBytes = self::DEFAULT_MAX_QUERY_VALUE_BYTES,
        int $maxDepth = self::DEFAULT_MAX_QUERY_DEPTH
    ): array {
        if ($queryParams === array() || $maxParams <= 0) {
            return array();
        }

        $result = array();
        $count = 0;

        foreach ($queryParams as $name => $value) {
            if ($count >= $maxParams) {
                break;
            }

            if (!is_string($name) || $name === '') {
                continue;
            }

            if (self::isForbiddenFieldName($name)) {
                continue;
            }

            $count++;

            $result[$name] = self::sanitizeSecurityValue(
                $value,
                0,
                $maxDepth,
                $maxValueBytes,
                $count,
                $maxParams
            );
        }

        return $result;
    }

    public static function captureSecurityBody(
        ?string $rawBody,
        ?string $contentType,
        int $maxBodyBytes = self::DEFAULT_MAX_BODY_BYTES,
        int $maxJsonDepth = self::DEFAULT_MAX_JSON_DEPTH
    ): FieldCaptureResult {
        if ($rawBody === null || $rawBody === '') {
            return FieldCaptureResult::empty();
        }

        $normalized = self::normalizeContentType($contentType);

        $isJson = is_string($normalized)
            && (
                $normalized === 'application/json'
                || self::endsWith($normalized, '+json')
            );

        if (
            !$isJson
            && $normalized !== 'application/x-www-form-urlencoded'
        ) {
            return new FieldCaptureResult(
                array(),
                false,
                false,
                true,
                false
            );
        }

        if ($maxBodyBytes <= 0 || strlen($rawBody) > $maxBodyBytes) {
            return new FieldCaptureResult(
                array(),
                false,
                true,
                false,
                false
            );
        }

        if ($isJson) {
            $hardCeiling = max(64, $maxJsonDepth + 16);

            try {
                $decoded = json_decode(
                    $rawBody,
                    true,
                    $hardCeiling,
                    JSON_THROW_ON_ERROR
                );
            } catch (\JsonException $e) {
                if (
                    strpos(
                        self::lower($e->getMessage()),
                        'depth'
                    ) !== false
                ) {
                    return new FieldCaptureResult(
                        array(),
                        false,
                        false,
                        false,
                        true
                    );
                }

                return new FieldCaptureResult(
                    array(),
                    true,
                    false,
                    false,
                    false
                );
            }

            if (!is_array($decoded)) {
                return new FieldCaptureResult(
                    array(),
                    true,
                    false,
                    false,
                    false
                );
            }

            if (self::depthOf($decoded) > $maxJsonDepth) {
                return new FieldCaptureResult(
                    array(),
                    false,
                    false,
                    false,
                    true
                );
            }

            $count = 0;

            $filtered = self::sanitizeSecurityValue(
                $decoded,
                0,
                $maxJsonDepth,
                self::DEFAULT_MAX_QUERY_VALUE_BYTES,
                $count,
                self::DEFAULT_MAX_QUERY_PARAMS
            );

            return new FieldCaptureResult(
                is_array($filtered) ? $filtered : array()
            );
        }

        $decoded = array();
        parse_str($rawBody, $decoded);

        if (self::depthOf($decoded) > $maxJsonDepth) {
            return new FieldCaptureResult(
                array(),
                false,
                false,
                false,
                true
            );
        }

        $count = 0;

        $filtered = self::sanitizeSecurityValue(
            $decoded,
            0,
            $maxJsonDepth,
            self::DEFAULT_MAX_QUERY_VALUE_BYTES,
            $count,
            self::DEFAULT_MAX_QUERY_PARAMS
        );

        return new FieldCaptureResult(
            is_array($filtered) ? $filtered : array()
        );
    }

    public static function isForbiddenFieldName(string $name): bool
    {
        $lowered = self::lower($name);

        foreach (self::FORBIDDEN_FIELD_PATTERNS as $pattern) {
            if (strpos($lowered, $pattern) !== false) {
                return true;
            }
        }

        return false;
    }

    private static function sanitizeSecurityValue(
        $value,
        int $depth,
        int $maxDepth,
        int $maxValueBytes,
        int &$count,
        int $maxParams
    ) {
        if ($depth >= $maxDepth) {
            return '[depth-limited]';
        }

        if (is_array($value)) {
            $out = array();

            foreach ($value as $key => $nested) {
                if ($count >= $maxParams) {
                    break;
                }

                if (
                    is_string($key)
                    && self::isForbiddenFieldName($key)
                ) {
                    continue;
                }

                $count++;

                $out[$key] = self::sanitizeSecurityValue(
                    $nested,
                    $depth + 1,
                    $maxDepth,
                    $maxValueBytes,
                    $count,
                    $maxParams
                );
            }

            return $out;
        }

        if (is_string($value)) {
            return self::cutString($value, $maxValueBytes);
        }

        if (
            is_int($value)
            || is_float($value)
            || is_bool($value)
            || $value === null
        ) {
            return $value;
        }

        return self::cutString((string) $value, $maxValueBytes);
    }

    private static function cutString(
        string $value,
        int $maxBytes
    ): string {
        if ($maxBytes <= 0) {
            return '';
        }

        if (function_exists('mb_strcut')) {
            return mb_strcut(
                $value,
                0,
                $maxBytes,
                'UTF-8'
            );
        }

        return substr($value, 0, $maxBytes);
    }

    private static function depthOf(
        $value,
        int $current = 0
    ): int {
        if (!is_array($value) || $value === array()) {
            return $current;
        }

        $max = $current;

        foreach ($value as $nested) {
            $max = max(
                $max,
                self::depthOf(
                    $nested,
                    $current + 1
                )
            );
        }

        return $max;
    }

    private static function normalizeContentType(
        ?string $contentType
    ): ?string {
        if ($contentType === null) {
            return null;
        }

        $parts = explode(';', $contentType, 2);

        return self::lower(trim($parts[0]));
    }

    private static function lower(string $value): string
    {
        if (function_exists('mb_strtolower')) {
            return mb_strtolower($value, 'UTF-8');
        }

        return strtolower($value);
    }

    private static function endsWith(
        string $value,
        string $suffix
    ): bool {
        if ($suffix === '') {
            return true;
        }

        if (strlen($suffix) > strlen($value)) {
            return false;
        }

        return substr(
            $value,
            -strlen($suffix)
        ) === $suffix;
    }
}
