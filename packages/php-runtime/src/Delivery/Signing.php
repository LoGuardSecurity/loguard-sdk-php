<?php

declare(strict_types=1);

namespace LoGuard\Runtime\Delivery;

final class Signing
{
    public const SDK_NAME = 'loguard-php-runtime';
    public const SDK_VERSION = '0.1.0';

    /**
     * @param array<string, mixed> $payload
     */
    public static function buildBody(array $payload): string
    {
        return json_encode(
            $payload,
            JSON_UNESCAPED_SLASHES
            | JSON_UNESCAPED_UNICODE
            | JSON_THROW_ON_ERROR
        );
    }

    /**
     * Optional timestamp/requestId exist only to make protocol
     * parity independently testable.
     *
     * @return array<string, string>
     */
    public static function sign(
        string $apiKey,
        string $bodyBytes,
        ?int $timestamp = null,
        ?string $requestId = null
    ): array {
        $ts = (string) (
            $timestamp !== null
                ? $timestamp
                : time()
        );

        $signature = hash_hmac(
            'sha256',
            $ts . '.' . $bodyBytes,
            $apiKey
        );

        return array(
            'X-Api-Key' => $apiKey,
            'X-LoGuard-Timestamp' => $ts,
            'X-LoGuard-Signature' => 'sha256=' . $signature,
            'X-Request-ID' => $requestId !== null
                ? $requestId
                : self::uuidV4(),
            'Content-Type' => 'application/json',
            'User-Agent' => self::SDK_NAME
                . '/'
                . self::SDK_VERSION,
        );
    }

    public static function uuidV4(): string
    {
        $data = random_bytes(16);

        $data[6] = chr(
            (ord($data[6]) & 0x0f) | 0x40
        );

        $data[8] = chr(
            (ord($data[8]) & 0x3f) | 0x80
        );

        return vsprintf(
            '%s%s-%s-%s-%s-%s%s%s',
            str_split(bin2hex($data), 4)
        );
    }
}
