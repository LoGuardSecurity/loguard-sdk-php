<?php

declare(strict_types=1);

require __DIR__ . '/../../src/Http/FieldCaptureResult.php';
require __DIR__ . '/../../src/Http/FieldPolicy.php';

use LoGuard\Runtime\Http\FieldPolicy;

function check($condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, 'FAIL: ' . $message . PHP_EOL);
        exit(1);
    }

    echo 'PASS: ' . $message . PHP_EOL;
}

function countEntries(array $value): int
{
    $count = 0;

    foreach ($value as $nested) {
        $count++;

        if (is_array($nested)) {
            $count += countEntries($nested);
        }
    }

    return $count;
}

/* Forbidden-name contract */
foreach (array(
    'password',
    'PASSWORD',
    'user_password',
    'access_token',
    'my_access_token_value',
    'Authorization',
    'cookie',
    'session_id',
    'private_key',
    'client_secret',
    'card_number',
    'cvv',
    'otp',
    'auth_token',
) as $name) {
    check(
        FieldPolicy::isForbiddenFieldName($name),
        'forbidden field: ' . $name
    );
}

/* Query recursive redaction */
$query = FieldPolicy::captureSecurityQuery(array(
    'q' => "' OR 1=1--",
    'password' => 'DO-NOT-STORE',
    'nested' => array(
        'token' => 'DO-NOT-STORE',
        'safe' => '<script>alert(1)</script>',
    ),
));

check(
    !isset($query['password']),
    'query password stripped'
);

check(
    !isset($query['nested']['token']),
    'nested query token stripped'
);

check(
    isset($query['nested']['safe']),
    'nested safe query retained'
);

/* Value byte bound */
$query = FieldPolicy::captureSecurityQuery(array(
    'q' => str_repeat('A', 10000),
));

check(
    strlen($query['q']) === 4096,
    'query value capped at 4096 bytes'
);

/* One global query budget */
$left = array();
$right = array();

for ($i = 0; $i < 40; $i++) {
    $left['l' . $i] = 'v';
    $right['r' . $i] = 'v';
}

$query = FieldPolicy::captureSecurityQuery(array(
    'left' => $left,
    'right' => $right,
));

check(
    countEntries($query) <= 64,
    'query global entry budget <= 64'
);

/* Query depth */
$query = FieldPolicy::captureSecurityQuery(array(
    'a' => array(
        'b' => array(
            'c' => array(
                'd' => array(
                    'e' => 'payload',
                ),
            ),
        ),
    ),
));

check(
    isset($query['a']['b']['c']['d']['e'])
    && $query['a']['b']['c']['d']['e'] === '[depth-limited]',
    'query depth bounded'
);

/* Standard JSON */
$body = FieldPolicy::captureSecurityBody(
    '{"q":"attack","password":"DO-NOT-STORE"}',
    'application/json; charset=utf-8'
);

check(
    isset($body->fields['q']),
    'application/json captured'
);

check(
    !isset($body->fields['password']),
    'JSON secret stripped'
);

/* Vendor +json */
$body = FieldPolicy::captureSecurityBody(
    '{"q":"attack-shaped-value"}',
    'application/problem+json; charset=utf-8'
);

check(
    isset($body->fields['q'])
    && $body->fields['q'] === 'attack-shaped-value',
    'application/*+json captured'
);

/* Form */
$body = FieldPolicy::captureSecurityBody(
    'username=test&password=secret&q=%3Cscript%3E1%3C%2Fscript%3E',
    'application/x-www-form-urlencoded'
);

check(
    isset($body->fields['username']),
    'form field captured'
);

check(
    !isset($body->fields['password']),
    'form secret stripped'
);

/* Body global budget */
$body = FieldPolicy::captureSecurityBody(
    json_encode(array(
        'left' => $left,
        'right' => $right,
    )),
    'application/json'
);

check(
    countEntries($body->fields) <= 64,
    'body global entry budget <= 64'
);

/* Unsupported */
$body = FieldPolicy::captureSecurityBody(
    "\x00\x01\x02",
    'application/octet-stream'
);

check(
    $body->fields === array()
    && $body->unsupportedContentType === true,
    'binary body rejected'
);

/* Multipart */
$body = FieldPolicy::captureSecurityBody(
    '--boundary',
    'multipart/form-data; boundary=boundary'
);

check(
    $body->fields === array()
    && $body->unsupportedContentType === true,
    'multipart body rejected'
);

/* Missing Content-Type */
$body = FieldPolicy::captureSecurityBody(
    'q=test',
    null
);

check(
    $body->unsupportedContentType === true,
    'body without Content-Type rejected'
);

/* Oversized */
$body = FieldPolicy::captureSecurityBody(
    str_repeat('A', 33000),
    'application/json'
);

check(
    $body->tooLarge === true
    && $body->fields === array(),
    'oversized body rejected before parsing'
);

/* Malformed JSON */
$body = FieldPolicy::captureSecurityBody(
    '{"q":',
    'application/json'
);

check(
    $body->parseError === true,
    'malformed JSON flagged'
);

/* Scalar JSON */
$body = FieldPolicy::captureSecurityBody(
    '"hello"',
    'application/json'
);

check(
    $body->parseError === true,
    'scalar JSON rejected'
);

echo 'PHP RUNTIME FIELD POLICY CONTRACT: PASS' . PHP_EOL;
