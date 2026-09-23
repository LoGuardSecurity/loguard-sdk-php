<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Unit;

use LoGuard\Sdk\Dispatch\FileSpool;
use LoGuard\Sdk\Event;
use PHPUnit\Framework\TestCase;

final class FileSpoolTest extends TestCase
{
    public function testEnqueueClaimAndComplete(): void
    {
        $directory = sys_get_temp_dir() . '/loguard-test-' . bin2hex(random_bytes(6));
        $spool = new FileSpool($directory, 2);
        $event = new Event('http_error', '127.0.0.1', '/', 500, date(DATE_ATOM));

        $this->assertTrue($spool->enqueue($event));
        $claimed = $spool->claim();
        $this->assertCount(1, $claimed);
        $spool->complete($claimed, true);
        $this->assertSame([], glob($directory . '/*') ?: []);
        @rmdir($directory);
    }
}
