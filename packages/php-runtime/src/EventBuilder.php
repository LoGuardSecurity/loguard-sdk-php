<?php

declare(strict_types=1);

namespace LoGuard\Runtime;

final class EventBuilder
{
    /** @var string */
    private $env;

    /** @var string|null */
    private $service;

    /** @var int */
    private $maxEventBytes;

    public function __construct(
        string $env = 'production',
        ?string $service = null,
        int $maxEventBytes = 65536
    ) {
        $this->env = $env;
        $this->service = $service;
        $this->maxEventBytes = $maxEventBytes;
    }

    /**
     * @param array<string, mixed> $event
     * @return array<string, mixed>|null
     */
    public function build(array $event): ?array
    {
        try {
            $type = isset($event['type'])
                ? trim((string) $event['type'])
                : '';

            $ip = isset($event['ip'])
                ? trim((string) $event['ip'])
                : '';

            $path = isset($event['path'])
                ? trim((string) $event['path'])
                : '';

            $statusCode = isset($event['status_code'])
                ? (int) $event['status_code']
                : 0;

            if (
                $type === ''
                || $ip === ''
                || $path === ''
                || $statusCode < 100
                || $statusCode > 599
            ) {
                return null;
            }

            if (strpos($path, '/') !== 0) {
                $path = '/' . $path;
            }

            if (strlen($path) > 1024) {
                $path = substr($path, 0, 1024);
            }

            $meta = isset($event['meta'])
                && is_array($event['meta'])
                ? $event['meta']
                : array();

            $meta['env'] = $this->env;

            $service = array_key_exists('service', $event)
                ? $event['service']
                : $this->service;

            $userId = array_key_exists('user_id', $event)
                ? $event['user_id']
                : null;

            $ts = isset($event['ts'])
                && is_string($event['ts'])
                && $event['ts'] !== ''
                ? $event['ts']
                : gmdate('Y-m-d\TH:i:s\+00:00');

            $built = array(
                'type' => self::cut(
                    strtolower($type),
                    64
                ),
                'ip' => self::cut(
                    $ip,
                    64
                ),
                'path' => $path,
                'status_code' => $statusCode,
                'ts' => $ts,
                'user_id' => $userId !== null
                    ? self::cut(
                        (string) $userId,
                        128
                    )
                    : null,
                'service' => $service !== null
                    ? self::cut(
                        strtolower(
                            trim((string) $service)
                        ),
                        64
                    )
                    : null,
                'meta' => $meta,
            );

            $wire = $built;
            $wire['meta'] = (object) $wire['meta'];

            $encoded = json_encode(
                $wire,
                JSON_UNESCAPED_SLASHES
                | JSON_UNESCAPED_UNICODE
                | JSON_THROW_ON_ERROR
            );

            if (
                !is_string($encoded)
                || strlen($encoded) > $this->maxEventBytes
            ) {
                return null;
            }

            return $built;
        } catch (\Throwable $e) {
            return null;
        }
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
