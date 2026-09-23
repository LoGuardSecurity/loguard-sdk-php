<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Dispatch;

use LoGuard\Sdk\Contracts\EventSinkInterface;
use LoGuard\Sdk\Event;
use LoGuard\Sdk\Signing;

final class FileSpool implements EventSinkInterface
{
    public function __construct(
        private readonly string $directory,
        private readonly int $maxFiles = 10000
    ) {
    }

    public function enqueue(Event $event): bool
    {
        try {
            $this->ensureDirectory();
            if (count(glob($this->directory . '/*.json') ?: []) >= $this->maxFiles) {
                return false;
            }

            $name = sprintf('%s/%020d-%s.json', $this->directory, hrtime(true), bin2hex(random_bytes(8)));
            $temporary = $name . '.tmp';
            $body = Signing::buildBody($event->jsonSerialize()) . "\n";
            if (file_put_contents($temporary, $body, LOCK_EX) !== strlen($body)) {
                @unlink($temporary);
                return false;
            }
            @chmod($temporary, 0600);
            if (!@rename($temporary, $name)) {
                @unlink($temporary);
                return false;
            }

            return true;
        } catch (\Throwable) {
            return false;
        }
    }

    /** @return array<string, mixed>[] */
    public function claim(int $limit = 50): array
    {
        $this->ensureDirectory();
        $this->recoverStaleClaims();
        $events = [];
        foreach (array_slice(glob($this->directory . '/*.json') ?: [], 0, max(1, $limit)) as $path) {
            $claimed = $path . '.sending-' . getmypid();
            if (!@rename($path, $claimed)) {
                continue;
            }
            try {
                $decoded = json_decode((string) file_get_contents($claimed), true, 16, JSON_THROW_ON_ERROR);
                if (is_array($decoded)) {
                    $decoded['__spool_file'] = $claimed;
                    $events[] = $decoded;
                } else {
                    @unlink($claimed);
                }
            } catch (\Throwable) {
                @rename($claimed, $path);
            }
        }

        return $events;
    }

    private function recoverStaleClaims(int $afterSeconds = 300): void
    {
        $cutoff = time() - $afterSeconds;
        foreach (glob($this->directory . '/*.json.sending-*') ?: [] as $path) {
            if ((@filemtime($path) ?: time()) > $cutoff) {
                continue;
            }
            $original = preg_replace('/\.sending-\d+$/', '', $path);
            if (is_string($original)) {
                @rename($path, $original);
            }
        }
    }

    /** @param array<string, mixed>[] $events */
    public function complete(array $events, bool $success): void
    {
        foreach ($events as $event) {
            $path = $event['__spool_file'] ?? null;
            if (!is_string($path)) {
                continue;
            }
            if ($success) {
                @unlink($path);
            } else {
                @rename($path, preg_replace('/\.sending-\d+$/', '', $path) ?: $path . '.json');
            }
        }
    }

    private function ensureDirectory(): void
    {
        if (!is_dir($this->directory) && !@mkdir($this->directory, 0700, true) && !is_dir($this->directory)) {
            throw new \RuntimeException('Unable to create LoGuard spool directory');
        }
    }
}
