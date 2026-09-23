<?php

declare(strict_types=1);

use LoGuard\Sdk\Client;
use LoGuard\Sdk\Config;
use LoGuard\Sdk\Contracts\TransportInterface;
use LoGuard\Sdk\Http\FieldPolicy;

require dirname(__DIR__, 2) . '/vendor/autoload.php';

$transport = new class implements TransportInterface {
    /** @var array<string, mixed> */
    public array $payload = [];

    public function send(
        string $url,
        array $headers,
        array $payload,
        float $timeout,
        int $attempts,
        string $method = 'POST',
        string $apiKey = ''
    ): mixed {
        $this->payload = $payload;

        return [
            'ok' => true,
            'accepted' => 1,
            'alerts' => [],
        ];
    }
};

$client = new Client(new Config('lg_test_compatibility'), $transport);
$result = $client->event(
    type: 'http_request',
    ip: '127.0.0.1',
    path: '/compatibility',
    statusCode: 200,
    meta: [
        'auth_method' => 'webauthn',
        'access_token' => 'must-not-leave-process',
    ]
);

if (!$result->ok) {
    throw new RuntimeException('Expected successful ingest result');
}

$meta = $transport->payload['events'][0]['meta'] ?? null;
if (!$meta instanceof stdClass) {
    throw new RuntimeException('Expected meta to use the JSON object wire shape');
}

if (($meta->auth_method ?? null) !== 'webauthn') {
    throw new RuntimeException('Legitimate authentication metadata was removed');
}

if (property_exists($meta, 'access_token')) {
    throw new RuntimeException('Sensitive metadata was not removed');
}

$query = FieldPolicy::captureQuery(
    ['authentication_result', 'authorization'],
    [
        'authentication_result' => 'failed',
        'authorization' => 'Bearer secret',
    ]
);

if (($query['authentication_result'] ?? null) !== 'failed') {
    throw new RuntimeException('Expected allowlisted query metadata');
}

if (array_key_exists('authorization', $query)) {
    throw new RuntimeException('Authorization data was not removed');
}

fwrite(STDOUT, "Core compatibility smoke test passed.\n");
