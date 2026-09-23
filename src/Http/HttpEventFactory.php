<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Http;

final class HttpEventFactory
{
    /** @return array<string, mixed>|null */
    public function create(RequestContext $context, CapturePolicy $policy): ?array
    {
        if (!$policy->tracks($context->statusCode)) {
            return null;
        }

        $meta = ['method' => strtoupper($context->method)];
        $wantedHeaders = HeaderPolicy::sanitizeRequested($policy->headers);
        $headers = HeaderPolicy::collect($wantedHeaders, function (string $name) use ($context): ?string {
            foreach ($context->headers as $header => $value) {
                if (strcasecmp($header, $name) === 0) {
                    return is_array($value) ? implode(', ', $value) : $value;
                }
            }
            return null;
        });
        if ($headers !== []) {
            $meta['headers'] = $headers;
        }

        if ($context->routeName !== null) {
            $query = FieldPolicy::captureQuery(
                $policy->queryByRoute[$context->routeName] ?? [],
                $context->query
            );
            if ($query !== []) {
                $meta['query'] = $query;
            }

            $paths = $policy->bodyByRoute[$context->routeName] ?? [];
            if ($paths !== []) {
                $body = FieldPolicy::captureBody(
                    $paths,
                    $context->rawBody,
                    $context->contentType,
                    $policy->maxBodyBytes,
                    $policy->maxJsonDepth
                );
                $meta = [...$meta, ...$body->toMeta()];
            }
        }

        return [
            'type' => 'http_error',
            'ip' => ClientIp::resolve($context->directPeerIp, $context->forwardedFor, $policy->trustedProxies),
            'path' => '/' . ltrim($context->path, '/'),
            'status_code' => $context->statusCode,
            'user_id' => $context->userId,
            'meta' => $meta,
        ];
    }
}
