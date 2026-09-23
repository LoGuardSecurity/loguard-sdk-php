# Operations guide

## Production checklist

1. Store `LOGUARD_API_KEY` in the deployment secret store.
2. Keep the default HTTPS endpoint and TLS verification.
3. Configure trusted proxy CIDRs before using `X-Forwarded-For`.
4. Start with the default error statuses and empty field allowlists.
5. Use a queue worker or filesystem spool for web traffic.
6. Send dropped/spool-full callbacks to existing monitoring.
7. Test a benign request, a controlled detection event and a LoGuard outage.
8. Roll out to one instance before enabling the whole fleet.

## Spool worker

The application user needs read/write access to the spool directory; no other
user should have access. Run `SpoolWorker::runOnce()` repeatedly from an
external process. A failed batch is returned to the queue. Successfully sent
files are deleted only after the ingest request succeeds.

Monitor directory size, oldest file age, send errors and dropped events. A full
spool is an operational alert, not an application error.

## Updating

Pin a tested Composer version range and review release notes. Validate in CI on
every supported PHP version. During rollout, compare application latency and
error rate with SDK delivery metrics. Disable automatic capture first if a
rollback is needed; manual events can remain available to workers.
