<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Tests\Support;

use CBOR\ByteStringObject;
use CBOR\MapObject;
use CBOR\NegativeIntegerObject;
use CBOR\TextStringObject;
use CBOR\UnsignedIntegerObject;
use Jw1980\Passkey\Base64Url;
use OpenSSLAsymmetricKey;
use stdClass;

/**
 * A passkey authenticator in software (ES256, OpenSSL) for the tests. It answers WebAuthn options
 * the way a real authenticator and browser do: `clientDataJSON` with the challenge and origin,
 * authenticator data with the hash of the relying-party ID, the flags and the signature counter,
 * attestation format `none`, and an ECDSA signature over the authenticator data and client data.
 */
final class SoftPasskey
{
    /** User present. */
    public const UP = 0x01;

    /** User verified. */
    public const UV = 0x04;

    /** Backup eligible (a synced passkey). */
    public const BE = 0x08;

    /** Backed up. */
    public const BS = 0x10;

    private const ATTESTED = 0x40;

    public readonly string $credentialId;

    public int $counter = 0;

    /** The user handle a discoverable credential stores at registration. */
    public ?string $userHandle = null;

    private OpenSSLAsymmetricKey $key;

    public function __construct(?string $credentialId = null)
    {
        $key = openssl_pkey_new(['private_key_type' => OPENSSL_KEYTYPE_EC, 'curve_name' => 'prime256v1']);
        assert($key !== false);
        $this->key = $key;
        $this->credentialId = $credentialId ?? random_bytes(32);
    }

    /**
     * @param  array<string, mixed>  $options  The `publicKey` creation options.
     * @return array<string, mixed> `RegistrationResponseJSON`
     */
    public function register(array $options, string $origin, int $flags = self::UP | self::UV, ?string $type = null): array
    {
        $this->userHandle = Base64Url::decode($options['user']['id']);
        $clientData = self::clientData($type ?? 'webauthn.create', $options['challenge'], $origin);
        $authData = hash('sha256', $options['rp']['id'], true).chr($flags | self::ATTESTED).pack('N', $this->counter)
            .str_repeat("\0", 16).pack('n', strlen($this->credentialId)).$this->credentialId.$this->coseKey();
        $attestation = (string) MapObject::create()
            ->add(TextStringObject::create('fmt'), TextStringObject::create('none'))
            ->add(TextStringObject::create('attStmt'), MapObject::create())
            ->add(TextStringObject::create('authData'), ByteStringObject::create($authData));

        return [
            'id' => Base64Url::encode($this->credentialId),
            'rawId' => Base64Url::encode($this->credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64Url::encode($clientData),
                'attestationObject' => Base64Url::encode($attestation),
                'transports' => ['internal', 'hybrid'],
            ],
            'clientExtensionResults' => new stdClass,
            'authenticatorAttachment' => 'platform',
        ];
    }

    /**
     * @param  array<string, mixed>  $options  The `publicKey` request options.
     * @return array<string, mixed> `AuthenticationResponseJSON`
     */
    public function assert(
        array $options,
        string $origin,
        int $flags = self::UP | self::UV,
        bool $sendUserHandle = true,
        ?string $rpId = null,
        ?string $type = null,
    ): array {
        $this->counter++;
        $clientData = self::clientData($type ?? 'webauthn.get', $options['challenge'], $origin);
        $authData = hash('sha256', $rpId ?? $options['rpId'], true).chr($flags).pack('N', $this->counter);
        openssl_sign($authData.hash('sha256', $clientData, true), $signature, $this->key, OPENSSL_ALGO_SHA256);

        return [
            'id' => Base64Url::encode($this->credentialId),
            'rawId' => Base64Url::encode($this->credentialId),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => Base64Url::encode($clientData),
                'authenticatorData' => Base64Url::encode($authData),
                'signature' => Base64Url::encode($signature),
                'userHandle' => $sendUserHandle && $this->userHandle !== null ? Base64Url::encode($this->userHandle) : null,
            ],
            'clientExtensionResults' => new stdClass,
            'authenticatorAttachment' => 'platform',
        ];
    }

    private static function clientData(string $type, string $challenge, string $origin): string
    {
        return json_encode(
            ['type' => $type, 'challenge' => $challenge, 'origin' => $origin, 'crossOrigin' => false],
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES,
        );
    }

    private function coseKey(): string
    {
        $details = openssl_pkey_get_details($this->key);
        assert(is_array($details));
        $x = str_pad($details['ec']['x'], 32, "\0", STR_PAD_LEFT);
        $y = str_pad($details['ec']['y'], 32, "\0", STR_PAD_LEFT);

        return (string) MapObject::create()
            ->add(UnsignedIntegerObject::create(1), UnsignedIntegerObject::create(2))
            ->add(UnsignedIntegerObject::create(3), NegativeIntegerObject::create(-7))
            ->add(NegativeIntegerObject::create(-1), UnsignedIntegerObject::create(1))
            ->add(NegativeIntegerObject::create(-2), ByteStringObject::create($x))
            ->add(NegativeIntegerObject::create(-3), ByteStringObject::create($y));
    }
}
