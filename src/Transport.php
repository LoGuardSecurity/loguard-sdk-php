<?php

declare(strict_types=1);

namespace LoGuard\Sdk;

use LoGuard\Sdk\Exceptions\LoGuardAuthException;
use LoGuard\Sdk\Exceptions\LoGuardConflictException;
use LoGuard\Sdk\Exceptions\LoGuardConnectionException;
use LoGuard\Sdk\Exceptions\LoGuardException;
use LoGuard\Sdk\Exceptions\LoGuardNotFoundException;
use LoGuard\Sdk\Exceptions\LoGuardQuotaException;
use LoGuard\Sdk\Exceptions\LoGuardValidationException;

/**
 * Signed HTTP transport for the LoGuard PHP SDK.
 *
 * Deliberately built on ext-curl instead of adding an HTTP client
 * dependency (Guzzle/PSR-18): ext-curl ships with virtually every PHP
 * install, keeps the SDK's dependency footprint at zero for the core
 * package, and gives us low-level control over the security-relevant
 * knobs below that a generic HTTP client wrapper would otherwise hide.
 *
 * Security hardening (see docs/SECURITY.md):
 *  - TLS certificate + hostname verification is always on and is not
 *    configurable to "off" from application code.
 *  - HTTP redirects are never followed automatically. A 3xx from the
 *    ingest endpoint is treated as a connection error rather than
 *    silently re-sent (with the signed API key) to a second URL —
 *    this closes the unsafe-redirect / credential-leak-via-redirect
 *    class of bug entirely, rather than trying to validate targets.
 *  - Only http/https schemes are ever dispatched, closing off
 *    file://, gopher://, etc. schemes as an SSRF vector via a
 *    misconfigured base_url.
 *  - Response bodies are capped (see MAX_RESPONSE_BYTES) so a
 *    malicious or misbehaving server can't exhaust client memory.
 */
final class Transport
{
    private const RETRY_STATUSES = [500, 502, 503, 504];
    private const MAX_RESPONSE_BYTES = 5 * 1024 * 1024; // 5 MiB

    /**
     * @param array<string, string> $headers
     * @param array<string, mixed> $payload
     * @return mixed
     */
    public static function sendSync(
        string $url,
        array $headers,
        array $payload,
        float $timeout,
        int $retries,
        string $method = 'POST',
        string $apiKey = ''
    ) {
        $lastException = new LoGuardConnectionException('Unknown error');

        for ($attempt = 1; $attempt <= max(1, $retries); $attempt++) {
            try {
                if ($apiKey !== '' && $method === 'POST') {
                    $body = Signing::buildBody($payload);
                    $signedHeaders = Signing::sign($apiKey, $body);
                    [$status, $rawBody] = self::execute($url, $method, $signedHeaders, $body, $timeout);
                } else {
                    $body = Signing::buildBody($payload);
                    [$status, $rawBody] = self::execute($url, $method, $headers, $body, $timeout);
                }

                if (!in_array($status, self::RETRY_STATUSES, true)) {
                    return self::raiseForStatus($status, $rawBody);
                }

                $lastException = new LoGuardConnectionException("Server error {$status}");
            } catch (TransportIoException $e) {
                $lastException = new LoGuardConnectionException('Connection error: ' . $e->getMessage());
            }

            if ($attempt < $retries) {
                usleep((int) (0.4 * $attempt * 1_000_000));
            }
        }

        throw $lastException;
    }

    /**
     * @param array<string, string> $headers
     * @return mixed
     */
    public static function sendSyncNoBody(
        string $url,
        array $headers,
        float $timeout,
        int $retries,
        string $method = 'GET'
    ) {
        $lastException = new LoGuardConnectionException('Unknown error');

        for ($attempt = 1; $attempt <= max(1, $retries); $attempt++) {
            try {
                [$status, $rawBody] = self::execute($url, $method, $headers, null, $timeout);

                if (!in_array($status, self::RETRY_STATUSES, true)) {
                    return self::raiseForStatus($status, $rawBody);
                }

                $lastException = new LoGuardConnectionException("Server error {$status}");
            } catch (TransportIoException $e) {
                $lastException = new LoGuardConnectionException('Connection error: ' . $e->getMessage());
            }

            if ($attempt < $retries) {
                usleep((int) (0.4 * $attempt * 1_000_000));
            }
        }

        throw $lastException;
    }

    /**
     * @param array<string, string> $headers
     * @return array{0: int, 1: string}
     */
    private static function execute(string $url, string $method, array $headers, ?string $body, float $timeout): array
    {
        $ch = curl_init();
        if ($ch === false) {
            throw new TransportIoException('failed to initialize curl handle');
        }

        $headerLines = [];
        foreach ($headers as $name => $value) {
            $headerLines[] = $name . ': ' . $value;
        }

        $received = '';
        $writeFn = static function ($curlHandle, string $chunk) use (&$received): int {
            $received .= $chunk;
            if (strlen($received) > Transport::MAX_RESPONSE_BYTES) {
                // Returning a short count aborts the transfer (CURLE_WRITE_ERROR).
                return 0;
            }

            return strlen($chunk);
        };

        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_CUSTOMREQUEST => strtoupper($method),
            CURLOPT_HTTPHEADER => $headerLines,
            CURLOPT_RETURNTRANSFER => false,
            CURLOPT_WRITEFUNCTION => $writeFn,
            CURLOPT_HEADER => false,
            CURLOPT_FOLLOWLOCATION => false, // never auto-follow redirects (see class docblock)
            CURLOPT_MAXREDIRS => 0,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_CONNECTTIMEOUT => min(10, (int) ceil($timeout)),
            CURLOPT_TIMEOUT_MS => (int) ($timeout * 1000),
            CURLOPT_NOSIGNAL => true,
        ]);

        if ($body !== null && strtoupper($method) !== 'GET') {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        curl_exec($ch);
        $errno = curl_errno($ch);
        $error = curl_error($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        if ($errno !== 0) {
            throw new TransportIoException("curl error ({$errno}): {$error}");
        }

        return [$status, $received];
    }

    /**
     * @return mixed
     */
    private static function raiseForStatus(int $status, string $rawBody)
    {
        $decoded = null;
        try {
            $decoded = json_decode($rawBody, true, 16, JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            $decoded = null;
        }
        $d = is_array($decoded) ? $decoded : [];
        $snippet = substr($rawBody, 0, 400);

        if ($status === 401) {
            throw new LoGuardAuthException('Invalid API key');
        }
        if ($status === 402) {
            throw new LoGuardAuthException('Subscription expired — renew at loguard.org');
        }
        if ($status === 403) {
            $detail = $d['detail'] ?? $snippet;
            if ($detail === 'subscription_expired') {
                throw new LoGuardAuthException('Subscription expired — renew at loguard.org');
            }
            throw new LoGuardAuthException('Access denied: ' . (is_string($detail) ? $detail : json_encode($detail)));
        }
        if ($status === 404) {
            throw new LoGuardNotFoundException('Not found: ' . ($d['detail'] ?? $snippet));
        }
        if ($status === 409) {
            throw new LoGuardConflictException('Conflict: ' . ($d['detail'] ?? $snippet));
        }
        if ($status === 422) {
            throw new LoGuardValidationException('Validation error: ' . $snippet);
        }
        if ($status === 429) {
            $detail = $d['detail'] ?? [];
            if (is_array($detail) && ($detail['err'] ?? null) === 'usage_limit_exceeded') {
                throw new LoGuardQuotaException(sprintf(
                    "Monthly quota exceeded: %s/%s events on plan '%s'. Upgrade at loguard.org",
                    $detail['used'] ?? '?',
                    $detail['limit'] ?? '?',
                    $detail['plan'] ?? '?'
                ));
            }
            throw new LoGuardConnectionException('Rate limited: ' . $snippet);
        }
        if ($status >= 500) {
            throw new LoGuardConnectionException("Server error ({$status}): {$snippet}");
        }

        return $decoded;
    }
}

/**
 * Internal marker exception for network/transport-level failures
 * (DNS, TLS, connection reset, timeout) — always translated to
 * LoGuardConnectionException before crossing the public API boundary.
 */
final class TransportIoException extends \RuntimeException
{
}
