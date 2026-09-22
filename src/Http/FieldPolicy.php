<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Http;

/**
 * Opt-in, allowlist-based query/body field capture for HTTP middleware.
 *
 * Mirrors the design of HeaderPolicy (forbidden set enforced in code, not
 * just documented) but for query parameters and JSON request bodies,
 * which were not previously collected by this SDK at all (see
 * docs/SECURITY.md: "No request body or query string is ever collected
 * automatically" — this class is what makes that collection possible,
 * strictly opt-in and per-route).
 *
 * [WHAT THIS CANNOT GUARANTEE] Field-name-based redaction cannot catch a
 * secret embedded inside an otherwise innocuously-named field's free-text
 * value (e.g. a token pasted into a "comment" field). This must be
 * communicated to whoever configures track_body_json_paths, not silently
 * assumed away.
 */
final class FieldPolicy
{
    /**
     * Field names that are never forwarded, regardless of allowlist
     * configuration, checked as a case-insensitive substring match
     * against the field's own name (not its parent path).
     */
    public const FORBIDDEN_FIELD_PATTERNS = [
        'password', 'passwd', 'pwd', 'secret', 'token', 'access_token', 'refresh_token',
        'api_key', 'apikey', 'authorization', 'cookie', 'session', 'csrf', 'xsrf',
        'private_key', 'client_secret', 'ssn', 'card_number', 'card_num', 'cvv', 'cvc',
        'credit_card', 'pin', 'otp', 'auth',
    ];

    public const DEFAULT_MAX_BODY_BYTES = 32 * 1024;
    public const DEFAULT_MAX_JSON_DEPTH = 8;

    /**
     * @param string[] $allowedNames Exact query-parameter names to keep for this route.
     * @param array<string, mixed> $queryParams Already-parsed query parameters
     *        (e.g. Laravel's $request->query()) — this class does not parse
     *        raw query strings itself, since the framework's own parser
     *        already applies PHP's standard "last value wins" rule for
     *        duplicate scalar keys, and re-parsing independently would risk
     *        disagreeing with what the framework itself saw.
     * @return array<string, mixed>
     */
    public static function captureQuery(array $allowedNames, array $queryParams): array
    {
        if ($allowedNames === []) {
            return [];
        }

        $result = [];
        foreach ($allowedNames as $name) {
            if (!array_key_exists($name, $queryParams)) {
                continue;
            }
            if (self::isForbiddenFieldName($name)) {
                continue;
            }
            $result[$name] = self::stripForbidden($queryParams[$name]);
        }

        return $result;
    }

    /**
     * @param string[] $allowedJsonPaths Dot-separated paths, e.g. "user.email".
     *        A path whose final segment matches a forbidden pattern is
     *        never captured, even if explicitly listed here by mistake.
     * @param string|null $rawBody Already-buffered request body (Laravel's
     *        Request::getContent() caches the stream internally on first
     *        read, so calling it here never consumes what the app itself
     *        needs — see Symfony\Component\HttpFoundation\Request::getContent()).
     */
    public static function captureBody(
        array $allowedJsonPaths,
        ?string $rawBody,
        ?string $contentType,
        int $maxBodyBytes = self::DEFAULT_MAX_BODY_BYTES,
        int $maxJsonDepth = self::DEFAULT_MAX_JSON_DEPTH
    ): FieldCaptureResult {
        if ($allowedJsonPaths === [] || $rawBody === null || $rawBody === '') {
            return FieldCaptureResult::empty();
        }

        if (self::normalizeContentType($contentType) !== 'application/json') {
            // multipart/form-data, files, binary bodies, and anything else
            // that isn't JSON are never parsed, by design.
            return new FieldCaptureResult(unsupportedContentType: true);
        }

        if (strlen($rawBody) > $maxBodyBytes) {
            return new FieldCaptureResult(tooLarge: true);
        }

        // A generous hard ceiling well above any realistic maxJsonDepth:
        // json_decode() throws "Maximum stack depth exceeded" if given a
        // depth close to the real limit, which would otherwise be
        // misreported as a syntax/parse error instead of a depth problem.
        // The real limit is enforced by depthOf() below, after a
        // successful decode.
        $hardCeiling = max(64, $maxJsonDepth + 16);

        try {
            $decoded = json_decode($rawBody, true, $hardCeiling, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            if (str_contains($e->getMessage(), 'depth')) {
                return new FieldCaptureResult(depthExceeded: true);
            }

            return new FieldCaptureResult(parseError: true);
        }

        if (!is_array($decoded)) {
            return new FieldCaptureResult(parseError: true);
        }

        if (self::depthOf($decoded) > $maxJsonDepth) {
            return new FieldCaptureResult(depthExceeded: true);
        }

        $filtered = [];
        foreach ($allowedJsonPaths as $path) {
            $parts = explode('.', $path);
            $leaf = end($parts);
            if (self::isForbiddenFieldName((string) $leaf)) {
                continue;
            }

            $value = self::getByPath($decoded, $parts);
            if ($value === self::NOT_FOUND) {
                continue;
            }

            self::setByPath($filtered, $parts, self::stripForbidden($value));
        }

        return new FieldCaptureResult(fields: $filtered);
    }

    private const NOT_FOUND = "\0__loguard_not_found__\0";

    /** @param string[] $path */
    private static function getByPath(array $data, array $path): mixed
    {
        $current = $data;
        foreach ($path as $part) {
            if (!is_array($current) || !array_key_exists($part, $current)) {
                return self::NOT_FOUND;
            }
            $current = $current[$part];
        }

        return $current;
    }

    /** @param string[] $path */
    private static function setByPath(array &$target, array $path, mixed $value): void
    {
        $key = array_shift($path);
        if ($path === []) {
            $target[$key] = $value;

            return;
        }
        if (!isset($target[$key]) || !is_array($target[$key])) {
            $target[$key] = [];
        }
        self::setByPath($target[$key], $path, $value);
    }

    public static function isForbiddenFieldName(string $name): bool
    {
        $lowered = mb_strtolower($name);
        foreach (self::FORBIDDEN_FIELD_PATTERNS as $pattern) {
            if (str_contains($lowered, $pattern)) {
                return true;
            }
        }

        return false;
    }

    private static function stripForbidden(mixed $value): mixed
    {
        if (!is_array($value)) {
            return $value;
        }

        $out = [];
        foreach ($value as $k => $v) {
            if (is_string($k) && self::isForbiddenFieldName($k)) {
                continue;
            }
            $out[$k] = self::stripForbidden($v);
        }

        return $out;
    }

    private static function depthOf(mixed $value, int $current = 0): int
    {
        if (!is_array($value) || $value === []) {
            return $current;
        }

        $max = $current;
        foreach ($value as $v) {
            $max = max($max, self::depthOf($v, $current + 1));
        }

        return $max;
    }

    private static function normalizeContentType(?string $contentType): ?string
    {
        if ($contentType === null) {
            return null;
        }

        return mb_strtolower(trim(explode(';', $contentType, 2)[0]));
    }
}
