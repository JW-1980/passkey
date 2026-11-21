<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase;

use JsonException;
use OpenSSLAsymmetricKey;
use SensitiveParameter;

/**
 * The Firebase service account the auth hub signs custom tokens with. Whoever holds this key can
 * sign in as any user of the project: keep the JSON file outside the web root, readable only by the
 * hub's process, and never log it.
 */
final class ServiceAccount
{
    private function __construct(
        public readonly string $projectId,
        public readonly string $clientEmail,
        private readonly OpenSSLAsymmetricKey $privateKey,
        public readonly ?string $privateKeyId,
    ) {}

    /** Reads the JSON file Google's console gives for a service account. */
    public static function fromFile(string $path): self
    {
        if (! is_file($path) || ! is_readable($path)) {
            throw FirebaseException::configuration('The Firebase service account file is missing or not readable.');
        }

        return self::fromJson((string) file_get_contents($path));
    }

    public static function fromJson(#[SensitiveParameter] string $json): self
    {
        try {
            $data = json_decode($json, true, 8, JSON_THROW_ON_ERROR);
        } catch (JsonException $failure) {
            throw FirebaseException::configuration('The Firebase service account is not valid JSON.', $failure);
        }
        if (! is_array($data) || ($data['type'] ?? null) !== 'service_account') {
            throw FirebaseException::configuration('The Firebase service account JSON is not of type "service_account".');
        }
        $projectId = $data['project_id'] ?? null;
        $email = $data['client_email'] ?? null;
        $pem = $data['private_key'] ?? null;
        $keyId = $data['private_key_id'] ?? null;
        if (! is_string($projectId) || ! ProjectId::isValid($projectId)) {
            throw FirebaseException::configuration('The Firebase service account has no valid project_id.');
        }
        if (! is_string($email) || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            throw FirebaseException::configuration('The Firebase service account has no valid client_email.');
        }
        if (! is_string($pem)) {
            throw FirebaseException::configuration('The Firebase service account has no private_key.');
        }

        return self::fromParts($projectId, $email, $pem, is_string($keyId) ? $keyId : null);
    }

    public static function fromParts(string $projectId, string $clientEmail, #[SensitiveParameter] string $privateKeyPem, ?string $privateKeyId = null): self
    {
        $key = openssl_pkey_get_private($privateKeyPem);
        if ($key === false) {
            throw FirebaseException::configuration('The Firebase service account private key could not be read.');
        }
        $details = openssl_pkey_get_details($key);
        if (! is_array($details) || ($details['type'] ?? null) !== OPENSSL_KEYTYPE_RSA || ($details['bits'] ?? 0) < 2048) {
            throw FirebaseException::configuration('The Firebase service account key must be RSA of at least 2048 bits.');
        }
        if (! ProjectId::isValid($projectId)) {
            throw FirebaseException::configuration('The Firebase project ID is not valid.');
        }

        return new self($projectId, $clientEmail, $key, $privateKeyId);
    }

    /**
     * A throw-away account for the Firebase Auth emulator, which accepts custom tokens with any
     * signature. Only for `demo-` projects, which cannot exist outside the emulator.
     */
    public static function forEmulator(string $projectId): self
    {
        if (! ProjectId::isDemo($projectId)) {
            throw FirebaseException::configuration('An emulator service account is only allowed for a "demo-" project.');
        }
        $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        if ($key === false) {
            throw FirebaseException::configuration('No RSA key could be generated.');
        }

        return new self($projectId, "firebase-emulator@{$projectId}.iam.gserviceaccount.com", $key, null);
    }

    /**
     * Signs a JWT with the service account key (RS256).
     *
     * @param  array<string, mixed>  $payload
     *
     * @internal
     */
    public function sign(array $payload): string
    {
        $header = ['alg' => 'RS256', 'typ' => 'JWT'];
        if ($this->privateKeyId !== null && $this->privateKeyId !== '') {
            $header['kid'] = $this->privateKeyId;
        }

        return Jwt::signRs256($header, $payload, $this->privateKey);
    }

    /** @return array<string, string> Never the key. */
    public function __debugInfo(): array
    {
        return ['projectId' => $this->projectId, 'clientEmail' => $this->clientEmail];
    }
}
