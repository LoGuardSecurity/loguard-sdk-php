<?php
// No network, database, Composer or framework bootstrap.
declare(strict_types=1);
$root = dirname(__DIR__, 2);
spl_autoload_register(function ($name) use ($root) {
    foreach (array('LoGuard\\Sdk\\' => '/src/', 'LoGuard\\Runtime\\' => '/packages/php-runtime/src/') as $prefix => $dir) {
        if (strpos($name, $prefix) === 0) {
            $path = $root . $dir . str_replace('\\', '/', substr($name, strlen($prefix))) . '.php';
            if (is_file($path)) { require_once $path; }
        }
    }
});
$count = 0;
function verify($value): void { global $count; if (!$value) { throw new RuntimeException('Contract assertion failed'); } $count++; }
foreach (array('LoGuard\\Sdk\\Ai\\ContentPolicy', 'LoGuard\\Runtime\\Ai\\ContentPolicy') as $policy) {
    $clean = $policy::clean('ai_llm_request', array('prompt' => str_repeat('a', 7000), 'system_prompt' => 'SYNTHETIC_PRIVATE_MARKER', 'messages' => array(array('role'=>'system','content'=>'SYNTHETIC_PRIVATE_MARKER'),array('role'=>'user','content'=>'hello')), '_ai_content_ref'=>'forged'));
    verify(strlen($clean['prompt']) === 7000);
    verify(strpos(json_encode($clean), 'SYNTHETIC_PRIVATE_MARKER') === false);
    verify(!isset($clean['_ai_content_ref']) && count($clean['messages']) === 1);
    $clean = $policy::clean('ai_tool_call', array('tool_name'=>'search_documents','tool_args'=>array(),'success'=>true));
    verify($clean['tool_args'] instanceof stdClass && json_encode($clean['tool_args']) === '{}');
    foreach (array(array('prompt'=>str_repeat('a',8001)),array('prompt'=>''),array('prompt'=>"\xff")) as $invalid) {
        $denied=false;try {$policy::clean('ai_llm_request',$invalid);} catch (InvalidArgumentException $e) {$denied=true;} verify($denied);
    }
    $denied=false;try {$policy::clean('ai_tool_call',array('tool_name'=>'x','tool_args'=>array(),'success'=>'yes'));} catch (InvalidArgumentException $e) {$denied=true;} verify($denied);
}
$dir=sys_get_temp_dir().'/loguard-ai-spool-check-'.bin2hex(random_bytes(8));
$runtimeSpool=new LoGuard\Runtime\Dispatch\FileSpool($dir);
verify($runtimeSpool->enqueue(array('type'=>'ai_llm_request','meta'=>array('prompt'=>'synthetic'))) === false && !file_exists($dir));
$builder=new LoGuard\Runtime\EventBuilder();
$built=$builder->build(array('type'=>'ai_tool_call','ip'=>'203.0.113.10','path'=>'/ai/test','status_code'=>200,'meta'=>array('tool_name'=>'search_documents','tool_args'=>array())));
verify($built !== null && $built['meta']['tool_args'] instanceof stdClass);
if (PHP_VERSION_ID >= 80100) {
    $e=new LoGuard\Sdk\Event('ai_llm_request','203.0.113.10','/ai/test',200,gmdate('c'),null,null,array('prompt'=>'synthetic'));
    verify((new LoGuard\Sdk\Dispatch\FileSpool($dir))->enqueue($e) === false && !file_exists($dir));
    $reflection=new ReflectionClass(LoGuard\Sdk\Client::class);$client=$reflection->newInstanceWithoutConstructor();
    foreach (array('config'=>new LoGuard\Sdk\Config('synthetic-key'),'sanitizer'=>new LoGuard\Sdk\Privacy\Sanitizer()) as $key=>$value) {
        $property=$reflection->getProperty($key);$property->setAccessible(true);$property->setValue($client,$value);
    }
    $method=$reflection->getMethod('buildEvent');$method->setAccessible(true);
    $event=$method->invoke($client,'ai_llm_request','203.0.113.10','/ai/test',200,null,null,array('prompt'=>str_repeat('x',7000)),null);
    verify(strlen($event->meta['prompt']) === 7000);
    // No sink, buffer or shutdown callback should receive asynchronous AI content.
    $client->eventAsync('ai_llm_request','203.0.113.10','/ai/test',200,null,null,array('prompt'=>'synthetic'));
    $pending=$reflection->getProperty('pending');$pending->setAccessible(true);verify($pending->getValue($client) === array());
    $method=new ReflectionMethod(LoGuard\Sdk\Transport::class,'raiseForStatus');$method->setAccessible(true);
    foreach (array(403,404,409,422,429,500) as $status) {
        $denied=false;try {$method->invoke(null,$status,'{"detail":{"err":"usage_limit_exceeded","plan":"SYNTHETIC_PRIVATE_MARKER"}}');}
        catch (Throwable $e) {$denied=strpos($e->getMessage(),'SYNTHETIC_PRIVATE_MARKER') === false;}
        verify($denied);
    }
}
echo json_encode(array('sdk'=>'php','state'=>'OFFLINE_PASS','cases'=>$count,'runtime'=>PHP_VERSION,'network'=>'none')).PHP_EOL;
