<?php

declare(strict_types=1);

namespace LoGuard\Runtime\Dispatch;

final class FileSpool
{
    /** @var string */
    private $directory;

    /** @var int */
    private $maxFiles;

    public function __construct(
        string $directory,
        int $maxFiles = 10000
    ) {
        $this->directory = rtrim($directory, '/');
        $this->maxFiles = $maxFiles;
    }

    /**
     * Persist one already-sanitized LoGuard event.
     *
     * @param array<string, mixed> $event
     */
    public function enqueue(array $event): bool
    {
        try {
            $this->ensureDirectory();

            if ($this->maxFiles <= 0) {
                return false;
            }

            if (
                count(glob($this->directory . '/*.json') ?: array())
                >= $this->maxFiles
            ) {
                return false;
            }

            $name = sprintf(
                '%s/%020d-%s.json',
                $this->directory,
                hrtime(true),
                bin2hex(random_bytes(8))
            );

            $temporary = $name . '.tmp';

            $payload = $event;

            if (
                array_key_exists('meta', $payload)
                && is_array($payload['meta'])
            ) {
                $payload['meta'] = (object) $payload['meta'];
            }

            $encoded = json_encode(
                $payload,
                JSON_UNESCAPED_SLASHES
                | JSON_UNESCAPED_UNICODE
                | JSON_THROW_ON_ERROR
            );

            $body = $encoded . "\n";

            $written = file_put_contents(
                $temporary,
                $body,
                LOCK_EX
            );

            if ($written !== strlen($body)) {
                @unlink($temporary);
                return false;
            }

            if (!@chmod($temporary, 0600)) {
                @unlink($temporary);
                return false;
            }

            if (!@rename($temporary, $name)) {
                @unlink($temporary);
                return false;
            }

            return true;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Claim queued events for background delivery.
     *
     * @return array<int, array<string, mixed>>
     */
    public function claim(int $limit = 50): array
    {
        try {
            $this->ensureDirectory();
            $this->recoverStaleClaims();

            $events = array();

            $paths = glob($this->directory . '/*.json') ?: array();
            sort($paths, SORT_STRING);

            $paths = array_slice(
                $paths,
                0,
                max(1, $limit)
            );

            foreach ($paths as $path) {
                $claimed = $path
                    . '.sending-'
                    . getmypid();

                if (!@rename($path, $claimed)) {
                    continue;
                }

                try {
                    $contents = file_get_contents($claimed);

                    if (!is_string($contents)) {
                        @rename($claimed, $path);
                        continue;
                    }

                    $decoded = json_decode(
                        $contents,
                        true,
                        16,
                        JSON_THROW_ON_ERROR
                    );

                    if (!is_array($decoded)) {
                        @unlink($claimed);
                        continue;
                    }

                    $decoded['__spool_file'] = $claimed;
                    $events[] = $decoded;
                } catch (\Throwable $e) {
                    @rename($claimed, $path);
                }
            }

            return $events;
        } catch (\Throwable $e) {
            return array();
        }
    }

    /**
     * @param array<int, array<string, mixed>> $events
     */
    public function complete(
        array $events,
        bool $success
    ): void {
        foreach ($events as $event) {
            $path = isset($event['__spool_file'])
                ? $event['__spool_file']
                : null;

            if (!is_string($path)) {
                continue;
            }

            if ($success) {
                @unlink($path);
                continue;
            }

            $original = preg_replace(
                '/\.sending-\d+$/',
                '',
                $path
            );

            if (
                !is_string($original)
                || $original === ''
            ) {
                $original = $path . '.json';
            }

            @rename($path, $original);
        }
    }

    private function recoverStaleClaims(
        int $afterSeconds = 300
    ): void {
        $cutoff = time() - $afterSeconds;

        foreach (
            glob($this->directory . '/*.json.sending-*')
            ?: array()
            as $path
        ) {
            $mtime = @filemtime($path);

            if (
                $mtime !== false
                && $mtime > $cutoff
            ) {
                continue;
            }

            $original = preg_replace(
                '/\.sending-\d+$/',
                '',
                $path
            );

            if (
                is_string($original)
                && $original !== ''
            ) {
                @rename($path, $original);
            }
        }
    }

    private function ensureDirectory(): void
    {
        if (
            !is_dir($this->directory)
            && !@mkdir(
                $this->directory,
                0700,
                true
            )
            && !is_dir($this->directory)
        ) {
            throw new \RuntimeException(
                'Unable to create LoGuard spool directory'
            );
        }

        @chmod($this->directory, 0700);
    }
}
