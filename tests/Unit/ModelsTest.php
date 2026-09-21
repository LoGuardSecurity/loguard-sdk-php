<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Unit;

use LoGuard\Sdk\Event;
use LoGuard\Sdk\IngestResult;
use PHPUnit\Framework\TestCase;

final class ModelsTest extends TestCase
{
    public function testIngestResultFromWellFormedResponse(): void
    {
        $result = IngestResult::fromResponse([
            'ok' => true,
            'accepted' => 3,
            'dropped' => 0,
            'alerts' => [
                ['kind' => 'brute_force', 'severity' => 'high', 'ip' => '1.2.3.4', 'path' => '/login', 'score' => 87, 'details' => []],
            ],
            'plan' => 'pro',
            'usage' => ['used' => 100, 'limit' => 1000, 'month' => '2026-09'],
        ]);

        $this->assertTrue($result->ok);
        $this->assertSame(3, $result->inserted);
        $this->assertSame(1, $result->alertsFired);
        $this->assertSame('brute_force', $result->alerts[0]->kind);
        $this->assertSame('pro', $result->plan);
        $this->assertSame(900, $result->usageInfo()->remaining());
        $this->assertFalse($result->usageInfo()->isNearLimit());
    }

    public function testIngestResultToleratesMalformedOrEmptyResponse(): void
    {
        // A malformed/partial server response must never crash the SDK --
        // callers should get sane, safe defaults instead of a fatal error.
        $result = IngestResult::fromResponse(null);
        $this->assertFalse($result->ok);
        $this->assertSame(0, $result->inserted);
        $this->assertSame([], $result->alerts);

        $result2 = IngestResult::fromResponse(['unexpected' => 'shape']);
        $this->assertFalse($result2->ok);
    }

    public function testUsageNearLimit(): void
    {
        $result = IngestResult::fromResponse(['usage' => ['used' => 850, 'limit' => 1000, 'month' => '2026-09']]);
        $this->assertTrue($result->usageInfo()->isNearLimit());
    }

    public function testUnlimitedPlanHasNoNearLimitWarning(): void
    {
        $result = IngestResult::fromResponse(['usage' => ['used' => 999999, 'limit' => 0, 'month' => '2026-09']]);
        $this->assertSame(-1, $result->usageInfo()->remaining());
        $this->assertFalse($result->usageInfo()->isNearLimit());
    }

    public function testEventJsonShapeMatchesIngestContract(): void
    {
        $event = new Event('login_failed', '1.2.3.4', '/login', 401, '2026-09-19T10:00:00+00:00', 'user_1', 'api', ['env' => 'production']);
        $json = json_decode((string) json_encode($event), true);

        $this->assertSame(['type', 'ip', 'path', 'status_code', 'ts', 'user_id', 'service', 'meta'], array_keys($json));
        $this->assertSame(401, $json['status_code']);
    }
}
