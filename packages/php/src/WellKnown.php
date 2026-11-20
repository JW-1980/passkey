<?php

declare(strict_types=1);

namespace Jw1980\Passkey;

use InvalidArgumentException;

/**
 * The association files that let native apps use the passkeys of a web domain. Serve them as JSON,
 * without redirects, from `https://<relying-party ID>/.well-known/…`.
 */
final class WellKnown
{
    /**
     * The origin an Android app sends in a passkey response: `android:apk-key-hash:` followed by the
     * base64url SHA-256 of its signing certificate. Add it to the relying party's allowed origins.
     *
     * @param  string  $fingerprint  The SHA-256 certificate fingerprint as `keytool` and the Play
     *                               Console print it (`AB:CD:…`, 32 bytes).
     */
    public static function androidOrigin(string $fingerprint): string
    {
        return 'android:apk-key-hash:'.Base64Url::encode(self::fingerprintBytes($fingerprint));
    }

    /**
     * Content of `/.well-known/assetlinks.json` (Digital Asset Links) for Android's Credential Manager.
     *
     * @param  list<string>  $fingerprints  SHA-256 certificate fingerprints (`AB:CD:…`).
     * @return list<array{relation: list<string>, target: array{namespace: string, package_name: string, sha256_cert_fingerprints: list<string>}}>
     */
    public static function assetLinks(string $packageName, array $fingerprints): array
    {
        if (preg_match('/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/', $packageName) !== 1) {
            throw new InvalidArgumentException('Not an Android package name.');
        }
        if ($fingerprints === []) {
            throw new InvalidArgumentException('At least one certificate fingerprint is needed.');
        }

        return [[
            'relation' => ['delegate_permission/common.handle_all_urls', 'delegate_permission/common.get_login_creds'],
            'target' => [
                'namespace' => 'android_app',
                'package_name' => $packageName,
                'sha256_cert_fingerprints' => array_map(
                    static fn (string $f): string => strtoupper(implode(':', str_split(bin2hex(self::fingerprintBytes($f)), 2))),
                    $fingerprints,
                ),
            ],
        ]];
    }

    /**
     * Content of `/.well-known/apple-app-site-association` for passkeys in iOS apps.
     *
     * @param  list<string>  $appIds  `<Team ID>.<bundle identifier>`
     * @return array{webcredentials: array{apps: list<string>}}
     */
    public static function appleAppSiteAssociation(array $appIds): array
    {
        foreach ($appIds as $appId) {
            if (preg_match('/^[A-Z0-9]{10}\.[A-Za-z0-9.-]+$/', $appId) !== 1) {
                throw new InvalidArgumentException("'{$appId}' is not a <Team ID>.<bundle identifier>.");
            }
        }
        if ($appIds === []) {
            throw new InvalidArgumentException('At least one app ID is needed.');
        }

        return ['webcredentials' => ['apps' => array_values($appIds)]];
    }

    private static function fingerprintBytes(string $fingerprint): string
    {
        $hex = str_replace(':', '', trim($fingerprint));
        if (preg_match('/^[0-9A-Fa-f]{64}$/', $hex) !== 1) {
            throw new InvalidArgumentException('A certificate fingerprint is 32 bytes of hex, optionally separated by colons.');
        }

        return (string) hex2bin($hex);
    }
}
