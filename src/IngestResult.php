<?php

declare(strict_types=1);

namespace LoGuard\Sdk;

final class UsageInfo
{
    public int $used;
    public int $limit;
    public string $month;

    public function __construct(int $used, int $limit, string $month)
    {
        $this->used = $used;
        $this->limit = $limit;
        $this->month = $month;
    }

    /** @param array<string, mixed> $d */
    public static function fromArray(array $d): self
    {
        return new self((int) ($d['used'] ?? 0), (int) ($d['limit'] ?? 0), (string) ($d['month'] ?? ''));
    }

    public function remaining(): int
    {
        if ($this->limit <= 0) {
            return -1;
        }

        return max(0, $this->limit - $this->used);
    }

    public function isNearLimit(): bool
    {
        if ($this->limit <= 0) {
            return false;
        }

        return ($this->used / $this->limit) > 0.8;
    }
}

final class AlertOut
{
    public string $kind;
    public string $severity;
    public string $ip;
    public string $path;
    public int $score;
    /** @var array<string, mixed> */
    public array $details;

    /** @param array<string, mixed> $details */
    public function __construct(string $kind, string $severity, string $ip, string $path, int $score, array $details)
    {
        $this->kind = $kind;
        $this->severity = $severity;
        $this->ip = $ip;
        $this->path = $path;
        $this->score = $score;
        $this->details = $details;
    }

    /** @param array<string, mixed> $d */
    public static function fromArray(array $d): self
    {
        return new self(
            (string) ($d['kind'] ?? ''),
            (string) ($d['severity'] ?? ''),
            (string) ($d['ip'] ?? ''),
            (string) ($d['path'] ?? ''),
            (int) ($d['score'] ?? 0),
            (array) ($d['details'] ?? [])
        );
    }
}

final class IngestResult
{
    public bool $ok;
    public int $inserted;
    public int $dropped;
    public int $alertsFired;
    /** @var AlertOut[] */
    public array $alerts;
    public string $plan;
    /** @var array<string, mixed> */
    public array $usage;

    /**
     * @param AlertOut[] $alerts
     * @param array<string, mixed> $usage
     */
    public function __construct(bool $ok, int $inserted, int $dropped, int $alertsFired, array $alerts, string $plan, array $usage)
    {
        $this->ok = $ok;
        $this->inserted = $inserted;
        $this->dropped = $dropped;
        $this->alertsFired = $alertsFired;
        $this->alerts = $alerts;
        $this->plan = $plan;
        $this->usage = $usage;
    }

    public function usageInfo(): UsageInfo
    {
        return UsageInfo::fromArray($this->usage);
    }

    /** @param array<string, mixed>|null $d */
    public static function fromResponse($d): self
    {
        $d = is_array($d) ? $d : [];
        $rawAlerts = is_array($d['alerts'] ?? null) ? $d['alerts'] : [];

        return new self(
            (bool) ($d['ok'] ?? false),
            (int) ($d['accepted'] ?? ($d['inserted'] ?? 0)),
            (int) ($d['dropped'] ?? 0),
            count($rawAlerts),
            array_map(fn ($a) => AlertOut::fromArray((array) $a), $rawAlerts),
            (string) ($d['plan'] ?? ''),
            (array) ($d['usage'] ?? [])
        );
    }
}
