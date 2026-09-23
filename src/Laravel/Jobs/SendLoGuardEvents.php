<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Laravel\Jobs;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use LoGuard\Sdk\Client;

/**
 * Delivers a batch of already-built LoGuard events from a Laravel
 * queue worker.
 *
 * This is the recommended production path for non-blocking delivery:
 * unlike the core SDK's shutdown-function flush (which still runs
 * inside the web worker's process, just after the response), this job
 * runs on a completely separate worker process and gets Laravel's
 * queue retry/backoff semantics for free.
 *
 * Bounded by design: the job carries at most one batch (capped by the
 * caller, see LoGuardMiddleware), and Laravel's queue retry policy
 * (tries/backoff, configured via --tries/--backoff on the worker or
 * $tries/$backoff below) bounds retries -- this job does not loop or
 * retry internally, avoiding an uncontrolled retry storm on top of
 * whatever the queue layer already does.
 */
final class SendLoGuardEvents implements ShouldQueue
{
    use Dispatchable;
    use InteractsWithQueue;
    use Queueable;
    use SerializesModels;

    /** @var array<int, array<string, mixed>> */
    public array $events;

    public int $tries = 3;
    public int $backoff = 5;

    /**
     * @param array<int, array<string, mixed>> $events Plain arrays shaped like
     *        Client::eventBatch()'s input (type, ip, path, status_code, ...).
     */
    public function __construct(array $events)
    {
        $this->events = $events;
    }

    public function handle(Client $client): void
    {
        if (empty($this->events)) {
            return;
        }

        // Deliberately does not catch LoGuardException: letting it
        // propagate is what makes Laravel's queue worker apply the
        // $tries/$backoff policy above. Swallowing it here would mean
        // silently losing events on a transient failure instead of
        // retrying through the queue's own bounded mechanism.
        $client->eventBatch($this->events, 1);
    }
}
