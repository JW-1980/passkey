<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase;

use JsonException;
use Jw1980\Passkey\Base64Url;
use OpenSSLAsymmetricKey;

/**
 * The few JWT operations the bridge needs: compact serialization, RS256 signing and verification.
 * Deliberately small: only RS256 is ever produced or accepted (plus `none` for the emulator, which
 * {@see IdTokenVerifier} allows only in an explicit emulator mode).
 *
 * @internal
 */
final class Jwt
{
    /**
     * @param  array<string, mixed>  $header
     * @param  array<string, mixed>  $payload
     */
    public static function signRs256(array $header, array $payload, OpenSSLAsymmetricKey $privateKey): string
    {
        $input = self::segment($header).'.'.self::segment($payload);
        if (! openssl_sign($input, $signature, $privateKey, OPENSSL_ALGO_SHA256)) {
            throw FirebaseException::configuration('The service account key could not sign.');
        }

        return $input.'.'.Base64Url::encode($signature);
    }

    /**
     * Splits and decodes a compact JWT without checking anything.
     *
     * @return array{header: array<string, mixed>, payload: array<string, mixed>, signature: string, input: string}
     */
    public static function decode(string $jwt): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3 || strlen($jwt) > 16384) {
            throw FirebaseException::invalidToken('not a compact JWT');
        }
        $header = self::object($parts[0]);
        $payload = self::object($parts[1]);
        $signature = $parts[2] === '' ? '' : Base64Url::decode($parts[2]);
        if ($signature === null) {
            throw FirebaseException::invalidToken('signature is not base64url');
        }

        return ['header' => $header, 'payload' => $payload, 'signature' => $signature, 'input' => $parts[0].'.'.$parts[1]];
    }

    public static function verifyRs256(string $input, string $signature, string $publicKeyPem): bool
    {
        $key = openssl_pkey_get_public($publicKeyPem);
        if ($key === false) {
            return false;
        }
        $details = openssl_pkey_get_details($key);
        if (! is_array($details) || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA || ($details['bits'] ?? 0) < 2048) {
            return false;
        }

        return openssl_verify($input, $signature, $key, OPENSSL_ALGO_SHA256) === 1;
    }

    /** @param array<string, mixed> $data */
    private static function segment(array $data): string
    {
        return Base64Url::encode(json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }

    /** @return array<string, mixed> */
    private static function object(string $segment): array
    {
        $json = Base64Url::decode($segment);
        if ($json === null) {
            throw FirebaseException::invalidToken('segment is not base64url');
        }
        try {
            $value = json_decode($json, true, 16, JSON_THROW_ON_ERROR);
        } catch (JsonException $failure) {
            throw FirebaseException::invalidToken('segment is not JSON', $failure);
        }
        if (! is_array($value) || array_is_list($value) && $value !== []) {
            throw FirebaseException::invalidToken('segment is not a JSON object');
        }

        /** @var array<string, mixed> $value */
        return $value;
    }
}
