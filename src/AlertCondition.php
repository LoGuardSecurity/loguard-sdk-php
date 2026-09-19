<?php

declare(strict_types=1);

namespace LoGuard\Sdk;

final class AlertCondition implements \JsonSerializable
{
    public const FIELDS = ['ip', 'path', 'status_code', 'type', 'user_id', 'rate_per_minute', 'rate_per_hour'];
    public const OPS = ['eq', 'neq', 'gt', 'gte', 'lt', 'lte', 'contains', 'startswith', 'endswith', 'regex', 'in', 'not_in'];

    public string $field;
    public string $op;
    /** @var mixed */
    public $value;

    /** @param mixed $value */
    public function __construct(string $field, string $op, $value)
    {
        $this->field = $field;
        $this->op = $op;
        $this->value = $value;
    }

    /** @return array<string, mixed> */
    public function jsonSerialize(): array
    {
        return ['field' => $this->field, 'op' => $this->op, 'value' => $this->value];
    }

    /** @param array<string, mixed> $d */
    public static function fromArray(array $d): self
    {
        return new self((string) $d['field'], (string) $d['op'], $d['value'] ?? null);
    }
}
