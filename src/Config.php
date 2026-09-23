<?php

declare(strict_types=1);

namespace LoGuard\Sdk;

use LoGuard\Sdk\Exceptions\LoGuardAuthException;
use LoGuard\Sdk\Exceptions\LoGuardValidationException;

/**
 * Immutable LoGuard client configuration.
 *
 * Validation mirrors monitor.init() in the Python SDK: api_key is
 * required, base_url must be https:// unless the caller explicitly
 * opts into allow_insecure_transport (fail closed by default, same
 * rationale as every other LoGuard SDK — the API key travels on
 * every request and must never go over plaintext HTTP by accident).
 */
final class Config
{
    public const DEFAULT_BASE_URL = 'https://api.loguard.org';
    public const DEFAULT_TIMEOUT = 3.0;
    public const DEFAULT_RETRIES = 2;
    public const DEFAULT_MAX_EVENT_BYTES = 64 * 1024;

    public readonly string $apiKey;
    public readonly string $baseUrl;
    public readonly string $env;
    public readonly float $timeout;
    public readonly int $retries;
    public readonly ?string $service;
    public readonly bool $allowInsecureTransport;
    public readonly int $maxEventBytes;

    public function __construct(
        string $apiKey,
        string $baseUrl = self::DEFAULT_BASE_URL,
        string $env = 'production',
        float $timeout = self::DEFAULT_TIMEOUT,
        int $retries = self::DEFAULT_RETRIES,
        ?string $service = null,
        bool $allowInsecureTransport = false,
        int $maxEventBytes = self::DEFAULT_MAX_EVENT_BYTES
    ) {
        if (trim($apiKey) === '') {
            throw new LoGuardAuthException('api_key is required');
        }

        $baseUrl = rtrim(trim($baseUrl), '/');
        $parts = parse_url($baseUrl);
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])
            || isset($parts['user']) || isset($parts['pass']) || isset($parts['query']) || isset($parts['fragment'])) {
            throw new LoGuardValidationException('base_url must be an absolute URL without credentials, query or fragment');
        }
        $scheme = strtolower((string) $parts['scheme']);
        if (!in_array($scheme, ['http', 'https'], true)) {
            throw new LoGuardValidationException('base_url must use http:// or https://');
        }
        if ($scheme !== 'https') {
            if (!$allowInsecureTransport) {
                throw new LoGuardValidationException(
                    'base_url must use https:// -- your api_key is sent on every request and ' .
                    'must not travel over plaintext HTTP. If you really need HTTP (e.g. a local ' .
                    'proxy on a trusted network during development), pass allowInsecureTransport: true explicitly.'
                );
            }
            @trigger_error(
                'LoGuard SDK initialized with allowInsecureTransport=true -- api_key and request ' .
                'signatures are being sent over plaintext. Use this ONLY for local development on ' .
                'a trusted network, never against a real deployment.',
                E_USER_WARNING
            );
        }

        if (!is_finite($timeout) || $timeout < 0.1 || $timeout > 30.0) {
            throw new LoGuardValidationException('timeout must be between 0.1 and 30 seconds');
        }
        if ($retries < 1 || $retries > 5) {
            throw new LoGuardValidationException('retries must be between 1 and 5');
        }
        if ($maxEventBytes < 1024 || $maxEventBytes > 1024 * 1024) {
            throw new LoGuardValidationException('max_event_bytes must be between 1024 and 1048576');
        }

        $this->apiKey = trim($apiKey);
        $this->baseUrl = $baseUrl;
        $this->env = $env !== '' ? $env : 'production';
        $this->timeout = $timeout;
        $this->retries = $retries;
        $this->service = self::resolveService($service);
        $this->allowInsecureTransport = $allowInsecureTransport;
        $this->maxEventBytes = $maxEventBytes;
    }

    /**
     * Falls back to whatever OpenTelemetry env var conventions the
     * deployment already uses, so a service name only has to be set
     * once in infra (not once per call site) if the caller doesn't
     * pass one explicitly.
     */
    private static function resolveService(?string $explicit): ?string
    {
        if ($explicit !== null && $explicit !== '') {
            return $explicit;
        }

        $fromEnv = getenv('OTEL_SERVICE_NAME');
        if ($fromEnv === false || $fromEnv === '') {
            $fromEnv = getenv('SERVICE_NAME');
        }

        return $fromEnv !== false && $fromEnv !== '' ? $fromEnv : null;
    }

    /**
     * Build a Config from a plain associative array (as used by the
     * Laravel `config/loguard.php` file and framework-agnostic array configs).
     *
     * @param array<string, mixed> $c
     */
    public static function fromArray(array $c): self
    {
        return new self(
            (string) ($c['api_key'] ?? ''),
            (string) ($c['base_url'] ?? self::DEFAULT_BASE_URL),
            (string) ($c['env'] ?? 'production'),
            (float) ($c['timeout'] ?? self::DEFAULT_TIMEOUT),
            (int) ($c['retries'] ?? self::DEFAULT_RETRIES),
            isset($c['service']) ? (string) $c['service'] : null,
            (bool) ($c['allow_insecure_transport'] ?? false),
            (int) ($c['max_event_bytes'] ?? self::DEFAULT_MAX_EVENT_BYTES)
        );
    }

    public function ingestUrl(): string
    {
        return $this->baseUrl . '/v1/ingest';
    }

    /** @return array<string, string> */
    public function defaultHeaders(): array
    {
        return [
            'X-Api-Key' => $this->apiKey,
            'Content-Type' => 'application/json',
            'User-Agent' => Signing::SDK_NAME . '/' . Signing::SDK_VERSION,
        ];
    }
}
