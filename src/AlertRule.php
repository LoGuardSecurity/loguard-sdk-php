<?php

declare(strict_types=1);

namespace LoGuard\Sdk;

final class AlertRule implements \JsonSerializable
{
    public ?int $id = null;
    public string $name;
    /** @var AlertCondition[] */
    public array $conditions;
    public string $severity;
    /** @var string[] */
    public array $actions;
    public bool $enabled;
    public string $description;
    public string $logic;
    public int $cooldownSec;
    public ?string $createdAt = null;
    public ?string $updatedAt = null;

    /**
     * @param AlertCondition[] $conditions
     * @param string[] $actions
     */
    public function __construct(
        string $name,
        array $conditions,
        string $severity = 'medium',
        array $actions = ['notify'],
        bool $enabled = true,
        string $description = '',
        string $logic = 'and',
        int $cooldownSec = 60
    ) {
        $this->name = $name;
        $this->conditions = $conditions;
        $this->severity = $severity;
        $this->actions = $actions;
        $this->enabled = $enabled;
        $this->description = $description;
        $this->logic = $logic;
        $this->cooldownSec = $cooldownSec;
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return [
            'name' => $this->name,
            'conditions' => array_map(fn (AlertCondition $c) => $c->jsonSerialize(), $this->conditions),
            'severity' => $this->severity,
            'actions' => $this->actions,
            'enabled' => $this->enabled,
            'description' => $this->description,
            'logic' => $this->logic,
            'cooldown_sec' => $this->cooldownSec,
        ];
    }

    /** @param array<string, mixed> $d */
    public static function fromArray(array $d): self
    {
        $rule = new self(
            (string) $d['name'],
            array_map(fn ($c) => AlertCondition::fromArray($c), $d['conditions'] ?? []),
            (string) ($d['severity'] ?? 'medium'),
            $d['actions'] ?? ['notify'],
            (bool) ($d['enabled'] ?? true),
            (string) ($d['description'] ?? ''),
            (string) ($d['logic'] ?? 'and'),
            (int) ($d['cooldown_sec'] ?? 60)
        );
        $rule->id = isset($d['id']) ? (int) $d['id'] : null;
        $rule->createdAt = $d['created_at'] ?? null;
        $rule->updatedAt = $d['updated_at'] ?? null;

        return $rule;
    }
}
