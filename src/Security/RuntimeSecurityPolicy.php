<?php

declare(strict_types=1);

namespace LoGuard\Sdk\Security;

final class RuntimeSecurityPolicy
{
    private const FIXED = [
        '8.2' => '8.2.35',
        '8.3' => '8.3.36',
        '8.4' => '8.4.27',
        '8.5' => '8.5.12',
    ];

    /**
     * @return array<string, string|null>
     */
    public static function assess(string $version, bool $vendorBuild = false): array
    {
        $result = [
            'status' => 'UNKNOWN',
            'installed_version' => $version,
            'minimum_fixed_version' => null,
            'recommended_action' => 'Verify the PHP build against official upstream and vendor advisories.',
            'evidence_source' => 'unverified',
            'confidence' => 'low',
        ];

        if (!preg_match('/^(\d+)\.(\d+)\.(\d+)$/D', $version, $matches)) {
            return $result;
        }

        $major = (int) $matches[1];
        $minor = (int) $matches[2];
        $branch = $major . '.' . $minor;

        if ($major < 8 || ($major === 8 && $minor < 2)) {
            $result['status'] = 'UNSUPPORTED';
            $result['recommended_action'] = 'Upgrade to a supported PHP branch or consult the vendor maintenance policy.';
            $result['evidence_source'] = 'upstream_support_lifecycle';
            $result['confidence'] = 'high';
            return $result;
        }

        if (!isset(self::FIXED[$branch])) {
            return $result;
        }

        $fixed = self::FIXED[$branch];
        $result['minimum_fixed_version'] = $fixed;

        if ($vendorBuild) {
            $result['evidence_source'] = 'vendor_patch_status_unverified';
            $result['recommended_action'] = 'Check distribution security bulletin and installed package revision.';
            return $result;
        }

        $result['status'] = version_compare($version, $fixed, '>=') ? 'PATCHED' : 'VULNERABLE';
        $result['evidence_source'] = 'upstream_version_threshold';
        $result['confidence'] = 'high';
        $result['recommended_action'] = $result['status'] === 'PATCHED'
            ? 'Keep PHP updated and verify the active PHP-FPM build.'
            : 'Update upstream PHP to at least ' . $fixed . ', or verify a vendor security backport.';
        return $result;
    }
}
