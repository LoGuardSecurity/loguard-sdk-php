<?php

declare(strict_types=1);

require __DIR__ . '/../../src/Ai/ContentPolicy.php';
require __DIR__ . '/../../src/EventBuilder.php';
require __DIR__ . '/../../src/Dispatch/FileSpool.php';

use LoGuard\Runtime\Ai\ContentPolicy;
use LoGuard\Runtime\EventBuilder;
use LoGuard\Runtime\Dispatch\FileSpool;

function aiCheck($condition): void {
    if (!$condition) { throw new RuntimeException('AI runtime contract assertion failed'); }
}
$clean = ContentPolicy::clean('ai_llm_request', array(
    'prompt' => str_repeat('a', 7000), 'system_prompt' => 'SYNTHETIC_PRIVATE_MARKER',
    'messages' => array(array('role'=>'developer','content'=>'SYNTHETIC_PRIVATE_MARKER'))
));
aiCheck(strlen($clean['prompt']) === 7000);
aiCheck(strpos(json_encode($clean), 'SYNTHETIC_PRIVATE_MARKER') === false);
$event = (new EventBuilder())->build(array('type'=>'ai_tool_call', 'ip'=>'203.0.113.10',
    'path'=>'/ai/test','status_code'=>200,'meta'=>array('tool_name'=>'search_documents','tool_args'=>array())));
aiCheck($event !== null && $event['meta']['tool_args'] instanceof stdClass);
$directory = sys_get_temp_dir() . '/loguard-ai-contract-' . bin2hex(random_bytes(8));
aiCheck((new FileSpool($directory))->enqueue($event) === false && !file_exists($directory));
$denied=false;
try { ContentPolicy::clean('ai_llm_request', array('prompt'=>str_repeat('a',8001))); }
catch (InvalidArgumentException $error) { $denied=true; }
aiCheck($denied);
echo "AI_RUNTIME_CONTENT_CONTRACT_PASS\n";
