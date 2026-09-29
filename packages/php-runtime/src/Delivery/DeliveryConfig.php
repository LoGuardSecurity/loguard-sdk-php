<?php

declare(strict_types=1);

namespace LoGuard\Runtime\Delivery;

final class DeliveryConfig
{
    public const DEFAULT_BASE_URL = 'https://api.loguard.org';
    public const DEFAULT_TIMEOUT = 3.0;
    public const DEFAULT_RETRIES = 2;

    /** @var string */
    public $apiKey;

    /** @var string */
    public $baseUrl;

    /** @var float */
    public $timeout;

    /** @var int */
    public $retries;

    /** @var bool */
    public $allowInsecureTransport;

    public function __construct(
        string $apiKey,
        string $baseUrl = self::DEFAULT_BASE_URL,
        float $timeout = self::DEFAULT_TIMEOUT,
        int $retries = self::DEFAULT_RETRIES,
        bool $allowInsecureTransport = false
    ) {
        $apiKey = trim($apiKey);

        if ($apiKey === '') {
            throw new \InvalidArgumentException(
                'LOGUARD_API_KEY is required'
            );
        }

        $baseUrl = rtrim(trim($baseUrl), '/');
        $parts = parse_url($baseUrl);

        if (
            !is_array($parts)
            || empty($parts['scheme'])
            || empty($parts['host'])
            || isset($parts['user'])
            || isset($parts['pass'])
            || isset($parts['query'])
            || isset($parts['fragment'])
        ) {
            throw new \InvalidArgumentException(
                'base_url must be an absolute URL without credentials, query or fragment'
            );
        }

        $scheme = strtolower((string) $parts['scheme']);

        if (!in_array($scheme, array('http', 'https'), true)) {
            throw new \InvalidArgumentException(
                'base_url must use http or https'
            );
        }

        if (
            $scheme !== 'https'
            && !$allowInsecureTransport
        ) {
            throw new \InvalidArgumentException(
                'base_url must use https'
            );
        }

        if (
            !is_finite($timeout)
            || $timeout < 0.1
            || $timeout > 30.0
        ) {
            throw new \InvalidArgumentException(
                'timeout must be between 0.1 and 30 seconds'
            );
        }

        if ($retries < 1 || $retries > 5) {
            throw new \InvalidArgumentException(
                'retries must be between 1 and 5'
            );
        }

        $this->apiKey = $apiKey;
        $this->baseUrl = $baseUrl;
        $this->timeout = $timeout;
        $this->retries = $retries;
        $this->allowInsecureTransport = $allowInsecureTransport;
    }

    public function ingestUrl(): string
    {
        return $this->baseUrl . '/v1/ingest';
    }
}
