<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Tests\Support;

use Jw1980\Passkey\Base64Url;
use Jw1980\Passkey\Firebase\KeySource;
use Jw1980\Passkey\Firebase\ServiceAccount;
use OpenSSLAsymmetricKey;

/**
 * Test keys: a service account (our custom tokens) and a stand-in for Google's token signing key
 * (ID tokens), each a real RSA key, generated once per test run.
 */
final class FirebaseKeys implements KeySource
{
    public const PROJECT = 'shop-test-123';

    public const CLIENT_EMAIL = 'hub@shop-test-123.iam.gserviceaccount.com';

    public const KID = 'google-key-1';

    /** @var array<string, array{private: string, public: string}> */
    private static array $pairs = [];

    /** @return array{private: string, public: string} */
    public static function pair(string $name): array
    {
        if (! isset(self::$pairs[$name])) {
            $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
            assert($key instanceof OpenSSLAsymmetricKey);
            openssl_pkey_export($key, $private);
            $details = openssl_pkey_get_details($key);
            assert(is_array($details));
            self::$pairs[$name] = ['private' => (string) $private, 'public' => (string) $details['key']];
        }

        return self::$pairs[$name];
    }

    public static function serviceAccountJson(string $project = self::PROJECT): string
    {
        return json_encode([
            'type' => 'service_account',
            'project_id' => $project,
            'private_key_id' => 'sa-key-1',
            'private_key' => self::pair('service-account')['private'],
            'client_email' => self::CLIENT_EMAIL,
            'client_id' => '1234567890',
        ], JSON_THROW_ON_ERROR);
    }

    public static function serviceAccount(string $project = self::PROJECT): ServiceAccount
    {
        return ServiceAccount::fromJson(self::serviceAccountJson($project));
    }

    /** As {@see KeySource}: Google's current keys are the stand-in key under {@see KID}. */
    public function key(string $kid): ?string
    {
        return $kid === self::KID ? self::pair('google')['public'] : null;
    }

    /**
     * A Firebase ID token as Google would issue it, signed with the stand-in key.
     *
     * @param  array<string, mixed>  $overrides  Claims to change (null removes a claim).
     * @param  array<string, mixed>  $header
     */
    public static function idToken(int $now, array $overrides = [], array $header = ['alg' => 'RS256', 'kid' => self::KID, 'typ' => 'JWT'], string $signWith = 'google'): string
    {
        $claims = array_merge([
            'iss' => 'https://securetoken.google.com/'.self::PROJECT,
            'aud' => self::PROJECT,
            'auth_time' => $now - 30,
            'user_id' => 'firebase-uid-1',
            'sub' => 'firebase-uid-1',
            'iat' => $now - 30,
            'exp' => $now + 3570,
            'email' => 'ann@example.com',
            'email_verified' => true,
            'firebase' => ['identities' => ['email' => ['ann@example.com']], 'sign_in_provider' => 'password'],
        ], $overrides);
        $claims = array_filter($claims, static fn ($value) => $value !== null);
        $input = Base64Url::encode((string) json_encode($header)).'.'.Base64Url::encode((string) json_encode($claims));
        if (($header['alg'] ?? null) === 'none') {
            return $input.'.';
        }
        openssl_sign($input, $signature, self::pair($signWith)['private'], OPENSSL_ALGO_SHA256);

        return $input.'.'.Base64Url::encode($signature);
    }
}
