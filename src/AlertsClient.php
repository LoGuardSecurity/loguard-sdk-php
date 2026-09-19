<?php

declare(strict_types=1);

namespace LoGuard\Sdk;

use LoGuard\Sdk\Exceptions\LoGuardValidationException;

/**
 * Manage user-defined alert rules — mirrors monitor.alerts in the
 * other LoGuard SDKs. Access via Client::alerts().
 *
 * Note on signing (matches every other SDK): only POST requests are
 * HMAC-signed by the transport layer. GET/PUT/DELETE requests here
 * are sent with the plain X-Api-Key header, matching the ingest
 * backend's current contract — do not "fix" this without confirming
 * the backend also expects signed GET/PUT/DELETE, or you will break
 * calls that currently succeed.
 */
final class AlertsClient
{
    private Client $client;

    public function __construct(Client $client)
    {
        $this->client = $client;
    }

    public function create(AlertRule $rule): AlertRule
    {
        $config = $this->client->config();
        $data = Transport::sendSync(
            $config->alertRulesUrl(),
            $config->defaultHeaders(),
            $rule->jsonSerialize(),
            $config->timeout,
            $config->retries,
            'POST',
            $config->apiKey
        );

        return AlertRule::fromArray(is_array($data) ? $data : []);
    }

    /** @return AlertRule[] */
    public function list(): array
    {
        $config = $this->client->config();
        $data = Transport::sendSyncNoBody(
            $config->alertRulesUrl(),
            $config->defaultHeaders(),
            $config->timeout,
            $config->retries,
            'GET'
        );

        $items = is_array($data) && array_is_list($data) ? $data : (is_array($data) ? ($data['rules'] ?? []) : []);

        return array_map(fn ($d) => AlertRule::fromArray((array) $d), $items ?: []);
    }

    public function get(int $ruleId): AlertRule
    {
        $config = $this->client->config();
        $data = Transport::sendSyncNoBody(
            $config->alertRulesUrl($ruleId),
            $config->defaultHeaders(),
            $config->timeout,
            $config->retries,
            'GET'
        );

        return AlertRule::fromArray(is_array($data) ? $data : []);
    }

    public function update(AlertRule $rule): AlertRule
    {
        if ($rule->id === null) {
            throw new LoGuardValidationException('rule->id is required to update');
        }
        $config = $this->client->config();
        $data = Transport::sendSync(
            $config->alertRulesUrl($rule->id),
            $config->defaultHeaders(),
            $rule->jsonSerialize(),
            $config->timeout,
            $config->retries,
            'PUT',
            $config->apiKey
        );

        return AlertRule::fromArray(is_array($data) ? $data : []);
    }

    public function delete(int $ruleId): void
    {
        $config = $this->client->config();
        Transport::sendSyncNoBody(
            $config->alertRulesUrl($ruleId),
            $config->defaultHeaders(),
            $config->timeout,
            $config->retries,
            'DELETE'
        );
    }

    public function enable(int $ruleId): AlertRule
    {
        $rule = $this->get($ruleId);
        $rule->enabled = true;

        return $this->update($rule);
    }

    public function disable(int $ruleId): AlertRule
    {
        $rule = $this->get($ruleId);
        $rule->enabled = false;

        return $this->update($rule);
    }
}
