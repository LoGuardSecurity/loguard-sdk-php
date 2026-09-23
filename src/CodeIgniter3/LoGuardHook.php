<?php

declare(strict_types=1);

namespace LoGuard\Sdk\CodeIgniter3;

use LoGuard\Sdk\Client;
use LoGuard\Sdk\Http\CapturePolicy;
use LoGuard\Sdk\Http\HttpEventFactory;
use LoGuard\Sdk\Http\RequestContext;

final class LoGuardHook
{
    public function __construct(
        private readonly Client $client,
        private readonly CapturePolicy $policy = new CapturePolicy(),
        private readonly HttpEventFactory $events = new HttpEventFactory()
    ) {
    }

    /**
     * Register this method as a CodeIgniter 3 post_system hook.
     * The hook intentionally uses only CI3's documented input/router/output APIs.
     */
    public function capture(): void
    {
        try {
            $ci = &get_instance();
            $headers = (array) $ci->input->request_headers();
            $event = $this->events->create(new RequestContext(
                (string) $ci->input->method(true),
                (string) $ci->uri->uri_string(),
                (int) (http_response_code() ?: 200),
                (string) ($ci->input->server('REMOTE_ADDR') ?: ''),
                $ci->input->get_request_header('X-Forwarded-For') ?: null,
                $ci->router->fetch_class() . '.' . $ci->router->fetch_method(),
                null,
                $headers,
                (array) $ci->input->get(),
                (string) $ci->input->raw_input_stream,
                $ci->input->get_request_header('Content-Type') ?: null
            ), $this->policy);

            if ($event !== null) {
                $this->client->eventAsync(
                    (string) $event['type'],
                    (string) $event['ip'],
                    (string) $event['path'],
                    (int) $event['status_code'],
                    null,
                    null,
                    (array) $event['meta']
                );
            }
        } catch (\Throwable) {
            // Hooks run after output; monitoring failures stay isolated.
        }
    }
}
