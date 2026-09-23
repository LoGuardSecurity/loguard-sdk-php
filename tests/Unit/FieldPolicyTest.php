<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Tests\Unit;

use LoGuard\Sdk\Http\FieldPolicy;
use PHPUnit\Framework\TestCase;

final class FieldPolicyTest extends TestCase
{
    // --- captureQuery() -------------------------------------------------

    public function testAllowlistedQueryParamIsCaptured(): void
    {
        $result = FieldPolicy::captureQuery(['q'], ['q' => 'hello', 'other' => 'x']);
        $this->assertSame(['q' => 'hello'], $result);
    }

    public function testNonAllowlistedQueryParamNeverLeaks(): void
    {
        $result = FieldPolicy::captureQuery(['q'], ['q' => 'hello', 'password' => 'leak']);
        $this->assertArrayNotHasKey('password', $result);
    }

    public function testForbiddenNamedQueryParamNeverCapturedEvenIfAllowlisted(): void
    {
        $result = FieldPolicy::captureQuery(['q', 'password'], ['q' => 'hello', 'password' => 'leak']);
        $this->assertArrayNotHasKey('password', $result, 'a forbidden-named field must never appear even if explicitly allowlisted');
    }

    public function testEmptyAllowlistCapturesNothing(): void
    {
        $result = FieldPolicy::captureQuery([], ['q' => 'hello']);
        $this->assertSame([], $result);
    }

    public function testDuplicateQueryParamsAreWhateverTheFrameworkAlreadyResolved(): void
    {
        // FieldPolicy does not re-parse query strings -- it trusts the
        // framework's own parsed array, which for Laravel/Symfony (like
        // PHP's native parse_str) already resolves duplicate scalar keys
        // to the last occurrence. This test documents that FieldPolicy
        // simply passes that resolved value through unchanged.
        $alreadyResolvedByFramework = ['a' => '2']; // as if "a=1&a=2" was parsed upstream
        $result = FieldPolicy::captureQuery(['a'], $alreadyResolvedByFramework);
        $this->assertSame('2', $result['a']);
    }

    // --- captureBody() ----------------------------------------------------

    public function testNestedAllowedPathIsCaptured(): void
    {
        $body = json_encode(['profile' => ['nickname' => 'zed', 'internal' => 'x']]);
        $result = FieldPolicy::captureBody(['profile.nickname'], $body, 'application/json');

        $this->assertSame('zed', $result->fields['profile']['nickname'] ?? null);
        $this->assertArrayNotHasKey('internal', $result->fields['profile'] ?? []);
    }

    public function testPasswordFieldNeverCapturedEvenIfAllowlisted(): void
    {
        $body = json_encode(['email' => 'a@b.com', 'password' => 'hunter2']);
        $result = FieldPolicy::captureBody(['email', 'password'], $body, 'application/json');

        $this->assertSame('a@b.com', $result->fields['email'] ?? null);
        $this->assertArrayNotHasKey('password', $result->fields);
    }

    public function testTokenLeafStrippedEvenWhenParentPathAllowlisted(): void
    {
        $body = json_encode(['nested' => ['token' => 'abc', 'safe' => 'ok']]);
        $result = FieldPolicy::captureBody(['nested.token', 'nested.safe'], $body, 'application/json');

        $this->assertArrayNotHasKey('token', $result->fields['nested'] ?? []);
        $this->assertSame('ok', $result->fields['nested']['safe'] ?? null);
    }

    public function testMalformedJsonDoesNotThrowAndIsFlagged(): void
    {
        $result = FieldPolicy::captureBody(['email'], '{"email": "a@b.com"', 'application/json'); // truncated

        $this->assertTrue($result->parseError);
        $this->assertSame([], $result->fields);
    }

    public function testOversizedBodyRejectedBeforeParsing(): void
    {
        $body = json_encode(['email' => str_repeat('x', 500)]);
        $result = FieldPolicy::captureBody(['email'], $body, 'application/json', maxBodyBytes: 100);

        $this->assertTrue($result->tooLarge);
        $this->assertSame([], $result->fields);
    }

    public function testMultipartContentTypeIsNeverParsed(): void
    {
        $result = FieldPolicy::captureBody(['email'], 'irrelevant bytes', 'multipart/form-data; boundary=xyz');

        $this->assertTrue($result->unsupportedContentType);
        $this->assertSame([], $result->fields);
    }

    public function testExcessiveDepthIsRejectedNotMisreportedAsParseError(): void
    {
        // Regression test: json_decode() throws "Maximum stack depth
        // exceeded" when handed a depth close to the real limit, which
        // must be classified as depthExceeded, not parseError -- these
        // are different signals for whoever monitors the integration.
        $body = json_encode(['a' => ['b' => ['c' => ['d' => ['e' => 'too deep']]]]]);
        $result = FieldPolicy::captureBody(['a.b.c.d.e'], $body, 'application/json', maxJsonDepth: 3);

        $this->assertTrue($result->depthExceeded);
        $this->assertFalse($result->parseError);
        $this->assertSame([], $result->fields);
    }

    public function testNoAllowlistCapturesNothingRegardlessOfBody(): void
    {
        $body = json_encode(['email' => 'a@b.com']);
        $result = FieldPolicy::captureBody([], $body, 'application/json');

        $this->assertSame([], $result->fields);
        $this->assertFalse($result->parseError);
    }

    public function testEmptyBodyCapturesNothing(): void
    {
        $result = FieldPolicy::captureBody(['email'], null, 'application/json');
        $this->assertSame([], $result->fields);

        $result2 = FieldPolicy::captureBody(['email'], '', 'application/json');
        $this->assertSame([], $result2->fields);
    }

    public function testIsForbiddenFieldNameIsCaseInsensitiveSubstringMatch(): void
    {
        $this->assertTrue(FieldPolicy::isForbiddenFieldName('Password'));
        $this->assertTrue(FieldPolicy::isForbiddenFieldName('user_PASSWORD_hash'));
        $this->assertFalse(FieldPolicy::isForbiddenFieldName('email'));
    }

    public function testLegitimateAuthenticationMetadataIsNotRemoved(): void
    {
        $captured = FieldPolicy::captureQuery(
            ['auth_method', 'authentication_result', 'authorization', 'auth_token'],
            [
                'auth_method' => 'webauthn',
                'authentication_result' => 'failed',
                'authorization' => 'Bearer secret',
                'auth_token' => 'secret',
            ]
        );

        $this->assertSame('webauthn', $captured['auth_method']);
        $this->assertSame('failed', $captured['authentication_result']);
        $this->assertArrayNotHasKey('authorization', $captured);
        $this->assertArrayNotHasKey('auth_token', $captured);
    }

}
