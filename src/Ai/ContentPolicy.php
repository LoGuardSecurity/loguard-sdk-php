<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Ai;

/** Explicit AI telemetry only. No disk delivery or system-message collection. */
final class ContentPolicy
{
    public static function isAi(string $type): bool
    {
        return in_array(strtolower(trim($type)), array(
            'ai_llm_request', 'ai_llm_response', 'ai_tool_call'
        ), true);
    }

    public static function clean(string $type, array $meta): array
    {
        $type = strtolower(trim($type));
        $fields = array('session_id' => 200, 'correlation_id' => 200, 'model' => 200, 'provider' => 100);
        $specific = array(
            'ai_llm_request' => array('prompt' => 8000),
            'ai_llm_response' => array('response' => 8000, 'finish_reason' => 100),
            'ai_tool_call' => array('tool_name' => 200, 'tool_result' => 8000)
        );
        if (!isset($specific[$type])) { self::fail(); }
        $out = array();
        foreach ($fields + $specific[$type] as $key => $limit) {
            if (array_key_exists($key, $meta)) {
                self::text($meta[$key], $limit);
                $out[$key] = $meta[$key];
            }
        }
        $required = array('ai_llm_request' => 'prompt', 'ai_llm_response' => 'response', 'ai_tool_call' => 'tool_name');
        if (!isset($out[$required[$type]]) || preg_match('/\S/u', $out[$required[$type]]) !== 1) { self::fail(); }
        if ($type === 'ai_llm_request') {
            foreach (array('messages' => 50, 'context_documents' => 10) as $key => $count) {
                if (!array_key_exists($key, $meta)) { continue; }
                if (!is_array($meta[$key]) || !self::isList($meta[$key]) || count($meta[$key]) > $count) { self::fail(); }
                $out[$key] = array();
                foreach ($meta[$key] as $item) {
                    if ($key === 'messages') {
                        if (!is_array($item) || !isset($item['role']) || !in_array($item['role'], array('system', 'developer', 'user', 'assistant', 'tool'), true)) { self::fail(); }
                        self::text(isset($item['content']) ? $item['content'] : null, 4000);
                        if (in_array($item['role'], array('system', 'developer'), true)) { continue; }
                        $out[$key][] = array('role' => $item['role'], 'content' => $item['content']);
                    } else {
                        self::text($item, 8000); $out[$key][] = $item;
                    }
                }
            }
        }
        $structured = $type === 'ai_tool_call' ? 'tool_args' : ($type === 'ai_llm_response' ? 'usage' : null);
        if ($structured !== null && array_key_exists($structured, $meta)) {
            $value = $meta[$structured];
            // PHP [] conventionally represents an empty object for tool arguments.
            if (is_array($value)) {
                if ($value !== array() && self::isList($value)) { self::fail(); }
                $value = (object) $value;
            }
            if (!is_string($value) && !($value instanceof \stdClass)) { self::fail(); }
            self::structured($value, 0);
            $json = self::encode($value);
            if (strlen($json) > 4000) { self::fail(); }
            $out[$structured] = json_decode($json, false, 16, JSON_THROW_ON_ERROR);
        } elseif ($type === 'ai_tool_call') { self::fail(); }
        if ($type === 'ai_tool_call' && array_key_exists('success', $meta)) {
            if (!is_bool($meta['success'])) { self::fail(); }
            $out['success'] = $meta['success'];
        }
        if (strlen(self::encode($out)) > 64000) { self::fail(); }
        // Always discard system_prompt, internal fields and unknown metadata.
        return $out;
    }

    private static function isList(array $value): bool
    {
        return $value === array() || array_keys($value) === range(0, count($value) - 1);
    }

    private static function text($value, int $limit): void
    {
        // Byte limits are conservative for UTF-8; never split or truncate content.
        if (!is_string($value) || strlen($value) > $limit || preg_match('//u', $value) !== 1) { self::fail(); }
    }

    private static function structured($value, int $depth): void
    {
        if ($depth > 6) { self::fail(); }
        if ($value === null || is_bool($value) || is_int($value)) { return; }
        if (is_float($value)) { if (!is_finite($value)) { self::fail(); } return; }
        if (is_string($value)) { self::text($value, 4000); return; }
        if (!is_array($value) && !($value instanceof \stdClass)) { self::fail(); }
        $items = (array) $value;
        if (count($items) > 50) { self::fail(); }
        foreach ($items as $key => $item) {
            if (!is_int($key)) { self::text($key, 128); }
            self::structured($item, $depth + 1);
        }
    }

    private static function encode($value): string
    {
        try { return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR); }
        catch (\Throwable $e) { self::fail(); }
    }

    private static function fail(): void
    {
        throw new \InvalidArgumentException('Invalid or oversized AI metadata');
    }
}
