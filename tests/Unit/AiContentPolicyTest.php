<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Unit;

use LoGuard\Sdk\Ai\ContentPolicy;
use LoGuard\Sdk\Dispatch\FileSpool;
use LoGuard\Sdk\Event;
use PHPUnit\Framework\TestCase;

final class AiContentPolicyTest extends TestCase
{
    public function testContentIsNotTruncatedAndSystemMessagesAreExcluded(): void
    {
        $meta = ContentPolicy::clean('ai_llm_request', [
            'prompt' => str_repeat('a', 7000),
            'system_prompt' => 'SYNTHETIC_PRIVATE_MARKER',
            'messages' => [['role' => 'developer', 'content' => 'SYNTHETIC_PRIVATE_MARKER']],
        ]);
        $this->assertSame(7000, strlen($meta['prompt']));
        $this->assertSame([], $meta['messages']);
        $this->assertArrayNotHasKey('system_prompt', $meta);
    }

    public function testOversizedContentIsRejectedRatherThanTruncated(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        ContentPolicy::clean('ai_llm_request', ['prompt' => str_repeat('a', 8001)]);
    }

    public function testEmptyToolArgumentsAreAnObject(): void
    {
        $meta = ContentPolicy::clean('ai_tool_call', ['tool_name' => 'search_documents', 'tool_args' => []]);
        $this->assertInstanceOf(\stdClass::class, $meta['tool_args']);
        $this->assertSame('{}', json_encode($meta['tool_args']));
    }

    public function testAiSpoolRefusesBeforeCreatingDirectory(): void
    {
        $directory = sys_get_temp_dir() . '/loguard-ai-phpunit-' . bin2hex(random_bytes(8));
        $event = new Event('ai_llm_request', '203.0.113.10', '/ai/test', 200, gmdate('c'),
            null, null, ['prompt' => 'synthetic']);
        $this->assertFalse((new FileSpool($directory))->enqueue($event));
        $this->assertDirectoryDoesNotExist($directory);
    }

    public function testAsyncAiDoesNotReachACustomQueueSink(): void
    {
        $sink = $this->createMock(\LoGuard\Sdk\Contracts\EventSinkInterface::class);
        $sink->expects($this->never())->method('enqueue');
        $client = new \LoGuard\Sdk\Client(new \LoGuard\Sdk\Config('synthetic-key'), eventSink: $sink);
        $client->eventAsync('ai_llm_request', '203.0.113.10', '/ai/test', 200,
            meta: ['prompt' => 'synthetic']);
    }

    public function testLaravelJobRejectsAiBeforeQueuePersistence(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        new \LoGuard\Sdk\Laravel\Jobs\SendLoGuardEvents([
            ['type' => 'ai_llm_request', 'meta' => ['prompt' => 'synthetic']],
        ]);
    }

}
