<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Unit;

use LoGuard\Sdk\Security\RuntimeSecurityPolicy;
use PHPUnit\Framework\TestCase;

final class RuntimeSecurityPolicyTest extends TestCase
{
    public function testUpstreamBoundaries(): void
    {
        $cases = [
            '8.2.34' => 'VULNERABLE', '8.2.35' => 'PATCHED',
            '8.3.35' => 'VULNERABLE', '8.3.36' => 'PATCHED',
            '8.4.26' => 'VULNERABLE', '8.4.27' => 'PATCHED',
            '8.5.11' => 'VULNERABLE', '8.5.12' => 'PATCHED',
            '7.4.33' => 'UNSUPPORTED', '8.0.30' => 'UNSUPPORTED',
            '8.1.99' => 'UNSUPPORTED', '8.6.0' => 'UNKNOWN',
            '8.5.12-dev' => 'UNKNOWN', 'invalid' => 'UNKNOWN',
        ];
        foreach ($cases as $version => $expected) {
            self::assertSame($expected, RuntimeSecurityPolicy::assess($version)['status'], $version);
        }
    }

    public function testVendorBackportIsNotAssumed(): void
    {
        $result = RuntimeSecurityPolicy::assess('8.4.26', true);
        self::assertSame('UNKNOWN', $result['status']);
        self::assertSame('vendor_patch_status_unverified', $result['evidence_source']);
    }

    public function testThresholdReported(): void
    {
        self::assertSame('8.4.27', RuntimeSecurityPolicy::assess('8.4.26')['minimum_fixed_version']);
    }
}
