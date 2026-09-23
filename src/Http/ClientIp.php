<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Http;

/**
 * Trusted-proxy-aware real-client-IP resolution.
 *
 * Port of loguard/_ip_utils.py (Python SDK) / the equivalent helper in
 * every other LoGuard SDK's HTTP middleware.
 *
 * Why this exists: anyone can put anything in X-Forwarded-For when
 * they make the request — it's just a header. The only time it's
 * safe to believe is when we know the request actually came through
 * a proxy we run (passed in via $trustedProxies); otherwise a visitor
 * could claim to be any IP they like and slip past IP-based checks
 * (rate limits, per-IP alerts, blocklists).
 *
 * With no trusted proxies configured, we simply never look at the
 * header — that's the default, not an opt-in.
 */
final class ClientIp
{
    /**
     * @param string $directPeerIp   The TCP-level remote address (e.g. $_SERVER['REMOTE_ADDR'],
     *                                or the equivalent already resolved by your webserver/framework).
     * @param string|null $xForwardedFor Raw X-Forwarded-For header value, if present.
     * @param string[] $trustedProxies IPs (or CIDRs) of proxies YOU control.
     */
    public static function resolve(string $directPeerIp, ?string $xForwardedFor, array $trustedProxies): string
    {
        if ($directPeerIp === '') {
            $directPeerIp = '127.0.0.1';
        }

        if ($xForwardedFor === null || $xForwardedFor === '' || empty($trustedProxies)) {
            return $directPeerIp;
        }

        if (!self::ipMatchesAny($directPeerIp, $trustedProxies)) {
            return $directPeerIp;
        }

        $chain = array_values(array_filter(array_map('trim', explode(',', $xForwardedFor)), [self::class, 'isValidIp']));
        $chain[] = $directPeerIp;
        for ($i = count($chain) - 1; $i >= 0; $i--) {
            if (!self::ipMatchesAny($chain[$i], $trustedProxies)) {
                return $chain[$i];
            }
        }

        return $directPeerIp;
    }

    private static function isValidIp(string $ip): bool
    {
        return filter_var($ip, FILTER_VALIDATE_IP) !== false;
    }

    /** @param string[] $trusted */
    private static function ipMatchesAny(string $ip, array $trusted): bool
    {
        foreach ($trusted as $entry) {
            if (strpos($entry, '/') !== false) {
                if (self::cidrMatch($ip, $entry)) {
                    return true;
                }
            } elseif ($entry === $ip) {
                return true;
            }
        }

        return false;
    }

    private static function cidrMatch(string $ip, string $cidr): bool
    {
        [$subnet, $maskLen] = array_pad(explode('/', $cidr, 2), 2, null);
        if ($subnet === null || $maskLen === null || !is_numeric($maskLen)) {
            return false;
        }

        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);
        if ($ipBin === false || $subnetBin === false || strlen($ipBin) !== strlen($subnetBin)) {
            return false;
        }

        $maskLen = (int) $maskLen;
        $maxBits = strlen($ipBin) * 8;
        if ($maskLen < 0 || $maskLen > $maxBits) {
            return false;
        }
        $bytes = intdiv($maskLen, 8);
        $bits = $maskLen % 8;

        if ($bytes > 0 && substr($ipBin, 0, $bytes) !== substr($subnetBin, 0, $bytes)) {
            return false;
        }
        if ($bits === 0) {
            return true;
        }

        $mask = chr((0xFF << (8 - $bits)) & 0xFF);
        $ipByte = substr($ipBin, $bytes, 1);
        $subnetByte = substr($subnetBin, $bytes, 1);

        return ($ipByte[0] & $mask) === ($subnetByte[0] & $mask);
    }
}
