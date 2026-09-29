<?php

declare(strict_types=1);

namespace LoGuard\Runtime\Delivery;

final class CurlTransport implements TransportInterface
{
    private const RETRY_STATUSES = array(
        500,
        502,
        503,
        504,
    );

    private const MAX_REQUEST_BYTES =
        5 * 1024 * 1024;

    private const MAX_RESPONSE_BYTES =
        5 * 1024 * 1024;

    /** @var DeliveryConfig */
    private $config;

    public function __construct(
        DeliveryConfig $config
    ) {
        $this->config = $config;
    }

    /**
     * @param array<int, array<string, mixed>> $events
     */
    public function send(array $events): IngestResult
    {
        $wireEvents = array();

        foreach ($events as $event) {
            if (
                isset($event['meta'])
                && is_array($event['meta'])
            ) {
                $event['meta'] =
                    (object) $event['meta'];
            }

            $wireEvents[] = $event;
        }

        $body = Signing::buildBody(array(
            'events' => $wireEvents,
        ));

        if (
            strlen($body)
            > self::MAX_REQUEST_BYTES
        ) {
            throw new \RuntimeException(
                'request body exceeds 5 MiB'
            );
        }

        $lastRetryable = null;

        for (
            $attempt = 1;
            $attempt <= $this->config->retries;
            $attempt++
        ) {
            try {
                list($status, $response) =
                    $this->execute($body);

                if (
                    in_array(
                        $status,
                        self::RETRY_STATUSES,
                        true
                    )
                ) {
                    throw new RetryableDeliveryException(
                        'server error '
                        . $status
                    );
                }

                if (
                    $status < 200
                    || $status >= 300
                ) {
                    throw new \RuntimeException(
                        'ingest returned HTTP '
                        . $status
                    );
                }

                try {
                    $decoded = json_decode(
                        $response,
                        true,
                        16,
                        JSON_THROW_ON_ERROR
                    );
                } catch (\JsonException $e) {
                    throw new \RuntimeException(
                        'invalid ingest JSON response',
                        0,
                        $e
                    );
                }

                if (!is_array($decoded)) {
                    throw new \RuntimeException(
                        'invalid ingest response'
                    );
                }

                return IngestResult::fromArray(
                    $decoded
                );
            } catch (RetryableDeliveryException $e) {
                $lastRetryable = $e;

                if (
                    $attempt
                    < $this->config->retries
                ) {
                    usleep(
                        (int) (
                            0.4
                            * $attempt
                            * 1000000
                        )
                    );

                    continue;
                }

                break;
            }
        }

        throw new \RuntimeException(
            'LoGuard delivery failed: '
            . (
                $lastRetryable !== null
                    ? $lastRetryable->getMessage()
                    : 'unknown error'
            ),
            0,
            $lastRetryable
        );
    }

    /**
     * @return array{0:int,1:string}
     */
    private function execute(
        string $body
    ): array {
        $ch = curl_init();

        if ($ch === false) {
            throw new RetryableDeliveryException(
                'failed to initialize curl'
            );
        }

        $headers = Signing::sign(
            $this->config->apiKey,
            $body
        );

        $headerLines = array();

        foreach ($headers as $name => $value) {
            $headerLines[] =
                $name . ': ' . $value;
        }

        $received = '';

        $writeFn = function (
            $handle,
            string $chunk
        ) use (&$received): int {
            $received .= $chunk;

            if (
                strlen($received)
                > self::MAX_RESPONSE_BYTES
            ) {
                return 0;
            }

            return strlen($chunk);
        };

        curl_setopt_array(
            $ch,
            array(
                CURLOPT_URL =>
                    $this->config->ingestUrl(),

                CURLOPT_CUSTOMREQUEST =>
                    'POST',

                CURLOPT_HTTPHEADER =>
                    $headerLines,

                CURLOPT_RETURNTRANSFER =>
                    false,

                CURLOPT_WRITEFUNCTION =>
                    $writeFn,

                CURLOPT_HEADER =>
                    false,

                CURLOPT_FOLLOWLOCATION =>
                    false,

                CURLOPT_MAXREDIRS =>
                    0,

                CURLOPT_PROTOCOLS =>
                    CURLPROTO_HTTP
                    | CURLPROTO_HTTPS,

                CURLOPT_REDIR_PROTOCOLS =>
                    CURLPROTO_HTTP
                    | CURLPROTO_HTTPS,

                CURLOPT_SSL_VERIFYPEER =>
                    true,

                CURLOPT_SSL_VERIFYHOST =>
                    2,

                CURLOPT_CONNECTTIMEOUT =>
                    min(
                        10,
                        (int) ceil(
                            $this->config->timeout
                        )
                    ),

                CURLOPT_TIMEOUT_MS =>
                    (int) (
                        $this->config->timeout
                        * 1000
                    ),

                CURLOPT_NOSIGNAL =>
                    true,

                CURLOPT_POSTFIELDS =>
                    $body,
            )
        );

        curl_exec($ch);

        $errno = curl_errno($ch);
        $error = curl_error($ch);

        $status = (int) curl_getinfo(
            $ch,
            CURLINFO_RESPONSE_CODE
        );

        curl_close($ch);

        if ($errno !== 0) {
            throw new RetryableDeliveryException(
                'curl error ('
                . $errno
                . '): '
                . $error
            );
        }

        return array(
            $status,
            $received,
        );
    }
}

final class RetryableDeliveryException
    extends \RuntimeException
{
}
