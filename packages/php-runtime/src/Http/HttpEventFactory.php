<?php

declare(strict_types=1);

namespace LoGuard\Runtime\Http;

final class HttpEventFactory
{
    /**
     * @return array<string, mixed>|null
     */
    public function create(
        RequestContext $context,
        CapturePolicy $policy
    ): ?array {
        if (!$policy->tracks(
            $context->statusCode
        )) {
            return null;
        }

        $meta = array(
            'method' => strtoupper(
                $context->method
            ),
        );

        $wantedHeaders = HeaderPolicy::sanitizeRequested(
            $policy->headers
        );

        $headers = HeaderPolicy::collect(
            $wantedHeaders,
            function (string $name) use ($context): ?string {
                foreach (
                    $context->headers
                    as $header => $value
                ) {
                    if (
                        !is_string($header)
                        || strcasecmp(
                            $header,
                            $name
                        ) !== 0
                    ) {
                        continue;
                    }

                    if (is_array($value)) {
                        $parts = array();

                        foreach ($value as $item) {
                            if (is_scalar($item)) {
                                $parts[] = (string) $item;
                            }
                        }

                        return implode(', ', $parts);
                    }

                    return is_scalar($value)
                        ? (string) $value
                        : null;
                }

                return null;
            }
        );

        if ($headers !== array()) {
            $meta['headers'] = $headers;
        }

        if ($policy->securityCapture) {
            $query = FieldPolicy::captureSecurityQuery(
                $context->query
            );

            if ($query !== array()) {
                $meta['query'] = $query;
            }

            $body = FieldPolicy::captureSecurityBody(
                $context->rawBody,
                $context->contentType,
                $policy->maxBodyBytes,
                $policy->maxJsonDepth
            );

            $meta = array_merge(
                $meta,
                $body->toMeta()
            );
        }

        return array(
            'type' => 'http_request',
            'ip' => ClientIp::resolve(
                $context->directPeerIp,
                $context->forwardedFor,
                $policy->trustedProxies
            ),
            'path' => '/'
                . ltrim(
                    $context->path,
                    '/'
                ),
            'status_code' => $context->statusCode,
            'user_id' => $context->userId,
            'meta' => $meta,
        );
    }
}
