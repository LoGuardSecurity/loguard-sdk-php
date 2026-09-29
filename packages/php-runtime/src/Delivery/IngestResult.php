<?php

declare(strict_types=1);

namespace LoGuard\Runtime\Delivery;

final class IngestResult
{
    /** @var bool */
    public $ok;

    /** @var int */
    public $accepted;

    /** @var int */
    public $dropped;

    /** @var string */
    public $plan;

    /** @var array<string, mixed> */
    public $usage;

    public function __construct(
        bool $ok,
        int $accepted,
        int $dropped,
        string $plan = '',
        array $usage = array()
    ) {
        $this->ok = $ok;
        $this->accepted = $accepted;
        $this->dropped = $dropped;
        $this->plan = $plan;
        $this->usage = $usage;
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self(
            (bool) ($data['ok'] ?? false),
            (int) (
                $data['accepted']
                ?? ($data['inserted'] ?? 0)
            ),
            (int) ($data['dropped'] ?? 0),
            (string) ($data['plan'] ?? ''),
            is_array($data['usage'] ?? null)
                ? $data['usage']
                : array()
        );
    }
}
