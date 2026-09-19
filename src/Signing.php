<?php

declare(strict_types=1);

namespace LoGuard\Sdk;

/**
 * Request signing for the LoGuard PHP SDK.
 *
 * Byte-for-byte the same protocol as the Python/Node/Go/C# SDKs
 * (see loguard/_signing.py, src/signing.js, loguard/signing.go,
 * Signing.cs): HMAC-SHA256 over "{unix_timestamp}." + body_bytes,
 * keyed with the raw API key. The server verifies:
 *
 *   1. X-LoGuard-Timestamp is fresh (< 5 minutes old) — replay protection.
 *   2. X-LoGuard-Signature matches HMAC-SHA256(api_key, "{ts}." + body).
 *
 * Only what was actually sent is ever signed: build the body first,
 * then sign those exact bytes, then send those exact bytes. Never
 * re-encode the payload between signing and sending.
 */
final class Signing
{
    public const SDK_NAME = 'loguard-php-sdk';
    public const SDK_VERSION = '1.0.0';

    /**
     * Serialize a payload to deterministic, compact JSON bytes.
     *
     * @param array<string, mixed> $payload
     */
    public static function buildBody(array $payload): string
    {
        $json = json_encode(
            $payload,
            JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR
        );

        return $json;
    }

    /**
     * Sign a request body and return [$bodyBytes, $headers].
     *
     * @return array{0: string, 1: array<string, string>}
     */
    public static function sign(string $apiKey, string $bodyBytes): array
    {
        $timestamp = (string) time();
        $signedPayload = $timestamp . '.' . $bodyBytes;
        $signature = hash_hmac('sha256', $signedPayload, $apiKey);

        $headers = [
            'X-Api-Key' => $apiKey,
            'X-LoGuard-Timestamp' => $timestamp,
            'X-LoGuard-Signature' => 'sha256=' . $signature,
            'X-Request-ID' => self::uuidV4(),
            'Content-Type' => 'application/json',
            'User-Agent' => self::SDK_NAME . '/' . self::SDK_VERSION,
        ];

        return [$bodyBytes, $headers];
    }

    public static function uuidV4(): string
    {
        $data = random_bytes(16);
        $data[6] = chr((ord($data[6]) & 0x0f) | 0x40);
        $data[8] = chr((ord($data[8]) & 0x3f) | 0x80);

        return vsprintf('%s%s-%s-%s-%s-%s%s%s', str_split(bin2hex($data), 4));
    }
}
