<?php

declare(strict_types=1);

namespace LoGuard\Runtime\Http;

final class ClientIp
{
    public static function resolve(
        string $directPeerIp,
        ?string $xForwardedFor,
        array $trustedProxies
    ): string {
        if ($directPeerIp === '') {
            $directPeerIp = '127.0.0.1';
        }

        if (
            $xForwardedFor === null
            || $xForwardedFor === ''
            || $trustedProxies === array()
        ) {
            return $directPeerIp;
        }

        if (!self::ipMatchesAny(
            $directPeerIp,
            $trustedProxies
        )) {
            return $directPeerIp;
        }

        $chain = array();

        foreach (
            explode(',', $xForwardedFor)
            as $candidate
        ) {
            $candidate = trim($candidate);

            if (self::isValidIp($candidate)) {
                $chain[] = $candidate;
            }
        }

        $chain[] = $directPeerIp;

        for (
            $i = count($chain) - 1;
            $i >= 0;
            $i--
        ) {
            if (!self::ipMatchesAny(
                $chain[$i],
                $trustedProxies
            )) {
                return $chain[$i];
            }
        }

        return $directPeerIp;
    }

    private static function isValidIp(
        string $ip
    ): bool {
        return filter_var(
            $ip,
            FILTER_VALIDATE_IP
        ) !== false;
    }

    private static function ipMatchesAny(
        string $ip,
        array $trusted
    ): bool {
        foreach ($trusted as $entry) {
            if (!is_string($entry)) {
                continue;
            }

            if (strpos($entry, '/') !== false) {
                if (self::cidrMatch($ip, $entry)) {
                    return true;
                }

                continue;
            }

            if ($entry === $ip) {
                return true;
            }
        }

        return false;
    }

    private static function cidrMatch(
        string $ip,
        string $cidr
    ): bool {
        $parts = array_pad(
            explode('/', $cidr, 2),
            2,
            null
        );

        $subnet = $parts[0];
        $maskLen = $parts[1];

        if (
            $subnet === null
            || $maskLen === null
            || !is_numeric($maskLen)
        ) {
            return false;
        }

        $ipBin = @inet_pton($ip);
        $subnetBin = @inet_pton($subnet);

        if (
            $ipBin === false
            || $subnetBin === false
            || strlen($ipBin) !== strlen($subnetBin)
        ) {
            return false;
        }

        $maskLen = (int) $maskLen;
        $maxBits = strlen($ipBin) * 8;

        if (
            $maskLen < 0
            || $maskLen > $maxBits
        ) {
            return false;
        }

        $bytes = intdiv($maskLen, 8);
        $bits = $maskLen % 8;

        if (
            $bytes > 0
            && substr($ipBin, 0, $bytes)
                !== substr($subnetBin, 0, $bytes)
        ) {
            return false;
        }

        if ($bits === 0) {
            return true;
        }

        $mask = chr(
            (0xFF << (8 - $bits)) & 0xFF
        );

        $ipByte = substr(
            $ipBin,
            $bytes,
            1
        );

        $subnetByte = substr(
            $subnetBin,
            $bytes,
            1
        );

        return ($ipByte[0] & $mask)
            === ($subnetByte[0] & $mask);
    }
}
