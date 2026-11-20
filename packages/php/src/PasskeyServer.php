<?php

declare(strict_types=1);

namespace Jw1980\Passkey;

use Cose\Algorithm\Manager;
use Cose\Algorithm\Signature\ECDSA\ES256;
use Cose\Algorithm\Signature\RSA\RS256;
use InvalidArgumentException;
use Jw1980\Passkey\Contracts\ChallengeStore;
use Jw1980\Passkey\Contracts\CredentialStore;
use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\NativeClock;
use Symfony\Component\Serializer\Normalizer\DenormalizerInterface;
use Symfony\Component\Uid\Uuid;
use Throwable;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\WebauthnSerializerFactory;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * The passkey relying party: starts and verifies registrations and sign-ins.
 *
 * Verification is done by web-auth/webauthn-lib; this class fixes the policy and keeps the state:
 *
 * - user verification is **required** (a passkey proves possession and a biometric or PIN);
 * - passkeys are **discoverable** (`residentKey: required`), so sign-in needs no username and the
 *   server reveals nothing about which accounts exist;
 * - no attestation is requested (`none`): the server learns nothing about the device model;
 * - ES256 and RS256;
 * - every challenge is random, single-use, bound to its purpose and expires;
 * - the signature counter must increase when the authenticator uses one (clone detection).
 */
final class PasskeyServer
{
    private const ALGORITHMS = [-7, -257];

    private const NAME_MAX = 100;

    private readonly ClockInterface $clock;

    /**
     * @param  string  $userHandleSecret  At least 32 bytes, kept on the server. The opaque user handle
     *                                    of an account is derived from it. Existing passkeys keep
     *                                    working when it changes, because each one stores its handle.
     */
    public function __construct(
        private readonly RelyingParty $relyingParty,
        private readonly CredentialStore $credentials,
        private readonly ChallengeStore $challenges,
        private readonly string $userHandleSecret,
        private readonly int $ceremonyTtlSeconds = 300,
        private readonly int $maxPasskeysPerUser = 10,
        ?ClockInterface $clock = null,
    ) {
        if (strlen($userHandleSecret) < 32) {
            throw new InvalidArgumentException('The user handle secret must be at least 32 bytes.');
        }
        if ($ceremonyTtlSeconds < 30 || $ceremonyTtlSeconds > 3600 || $maxPasskeysPerUser < 1) {
            throw new InvalidArgumentException('The ceremony lifetime must be 30 to 3600 seconds and the passkey limit at least 1.');
        }
        $this->clock = $clock ?? new NativeClock;
    }

    /** The opaque, stable handle (32 bytes) the authenticator stores for an account. */
    public function userHandle(string $userId): string
    {
        return hash_hmac('sha256', "passkey-user-handle\0".$userId, $this->userHandleSecret, true);
    }

    /** Starts registering a passkey for an account that is already signed in. */
    public function beginRegistration(PasskeyUser $user): Ceremony
    {
        $existing = $this->credentials->forUser($user->id);
        if (count($existing) >= $this->maxPasskeysPerUser) {
            throw PasskeyException::tooManyPasskeys($this->maxPasskeysPerUser);
        }
        $challenge = random_bytes(32);
        // An account keeps the handle of its first passkey, so the authenticator sees one account.
        $handle = $existing === [] ? $this->userHandle($user->id) : $existing[0]->userHandle;

        $id = $this->remember([
            'purpose' => 'register',
            'userHandle' => Base64Url::encode($handle),
            'challenge' => Base64Url::encode($challenge),
            'userId' => $user->id,
            'name' => $user->name,
            'displayName' => $user->displayName,
        ]);

        return new Ceremony($id, [
            'rp' => ['id' => $this->relyingParty->id, 'name' => $this->relyingParty->name],
            'user' => ['id' => Base64Url::encode($handle), 'name' => $user->name, 'displayName' => $user->displayName],
            'challenge' => Base64Url::encode($challenge),
            'pubKeyCredParams' => array_map(static fn (int $alg): array => ['type' => 'public-key', 'alg' => $alg], self::ALGORITHMS),
            'timeout' => $this->ceremonyTtlSeconds * 1000,
            // The authenticator refuses to create a second passkey for the same account.
            'excludeCredentials' => array_map(self::descriptor(...), $existing),
            'authenticatorSelection' => ['residentKey' => 'required', 'requireResidentKey' => true, 'userVerification' => 'required'],
            'attestation' => 'none',
            'extensions' => ['credProps' => true],
        ]);
    }

    /**
     * Verifies a registration and stores the passkey.
     *
     * @param  array<array-key, mixed>  $credential  The client's `RegistrationResponseJSON`.
     * @param  PasskeyUser  $user  The signed-in account; must be the one that started.
     */
    public function finishRegistration(string $ceremonyId, array $credential, PasskeyUser $user, ?string $name = null): StoredPasskey
    {
        $name = self::cleanName($name ?? 'Passkey');
        $state = $this->recall($ceremonyId, 'register');
        if (! hash_equals((string) ($state['userId'] ?? ''), $user->id)) {
            throw PasskeyException::ceremonyExpired();
        }

        try {
            $handle = self::bytes($state['userHandle'] ?? null);
            $response = $this->parse($credential)->response;
            if (! $response instanceof AuthenticatorAttestationResponse) {
                throw new InvalidArgumentException('Not a registration response.');
            }
            $options = PublicKeyCredentialCreationOptions::create(
                PublicKeyCredentialRpEntity::create($this->relyingParty->name, $this->relyingParty->id),
                PublicKeyCredentialUserEntity::create((string) $state['name'], $handle, (string) $state['displayName']),
                self::bytes($state['challenge'] ?? null),
                array_map(static fn (int $alg): PublicKeyCredentialParameters => PublicKeyCredentialParameters::createPk($alg), self::ALGORITHMS),
                AuthenticatorSelectionCriteria::create(
                    null,
                    AuthenticatorSelectionCriteria::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                    AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_REQUIRED,
                ),
                PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
                [],
                max(1, $this->ceremonyTtlSeconds * 1000),
            );
            $record = (new AuthenticatorAttestationResponseValidator($this->steps()->creationCeremony()))
                ->check($response, $options, $this->relyingParty->id);
        } catch (Throwable $failure) {
            throw PasskeyException::invalidRegistration($failure);
        }

        if ($this->credentials->countForUser($user->id) >= $this->maxPasskeysPerUser) {
            throw PasskeyException::tooManyPasskeys($this->maxPasskeysPerUser);
        }
        $passkey = new StoredPasskey(
            credentialId: $record->publicKeyCredentialId,
            userId: $user->id,
            userHandle: $handle,
            publicKey: $record->credentialPublicKey,
            counter: $record->counter,
            transports: self::transports($record->transports),
            aaguid: $record->aaguid->toRfc4122(),
            backupEligible: $record->backupEligible === true,
            backedUp: $record->backupStatus === true,
            attestationType: $record->attestationType,
            name: $name,
            createdAt: $this->clock->now(),
            lastUsedAt: null,
        );
        $this->credentials->add($passkey);

        return $passkey;
    }

    /**
     * Starts a sign-in. Without an account every discoverable passkey of this relying party may
     * answer. With an account (re-confirming someone who is already signed in) only that account's
     * passkeys are accepted.
     */
    public function beginAuthentication(?string $userId = null): Ceremony
    {
        $challenge = random_bytes(32);
        $allowed = $userId === null ? [] : $this->credentials->forUser($userId);
        if ($userId !== null && $allowed === []) {
            throw PasskeyException::invalidPasskey();
        }
        $id = $this->remember([
            'purpose' => 'login',
            'challenge' => Base64Url::encode($challenge),
            'userId' => $userId,
        ]);

        return new Ceremony($id, [
            'challenge' => Base64Url::encode($challenge),
            'timeout' => $this->ceremonyTtlSeconds * 1000,
            'rpId' => $this->relyingParty->id,
            'allowCredentials' => array_map(self::descriptor(...), $allowed),
            'userVerification' => 'required',
        ]);
    }

    /**
     * Verifies a sign-in and records the use of the passkey.
     *
     * @param  array<array-key, mixed>  $credential  The client's `AuthenticationResponseJSON`.
     */
    public function finishAuthentication(string $ceremonyId, array $credential): AuthenticationResult
    {
        $state = $this->recall($ceremonyId, 'login');
        $expectedUser = isset($state['userId']) ? (string) $state['userId'] : null;

        try {
            $public = $this->parse($credential);
            $response = $public->response;
            if (! $response instanceof AuthenticatorAssertionResponse) {
                throw new InvalidArgumentException('Not a sign-in response.');
            }
            $stored = $this->credentials->find($public->rawId);
            if ($stored === null || ($expectedUser !== null && ! hash_equals($stored->userId, $expectedUser))) {
                throw new InvalidArgumentException('Unknown passkey.');
            }
            $options = PublicKeyCredentialRequestOptions::create(
                self::bytes($state['challenge'] ?? null),
                $this->relyingParty->id,
                [],
                PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
                max(1, $this->ceremonyTtlSeconds * 1000),
            );
            // Without a known account the response must carry the user handle of the passkey.
            $record = (new AuthenticatorAssertionResponseValidator($this->steps()->requestCeremony()))->check(
                self::record($stored),
                $response,
                $options,
                $this->relyingParty->id,
                $expectedUser === null ? null : $stored->userHandle,
            );
        } catch (Throwable $failure) {
            throw PasskeyException::invalidPasskey($failure);
        }

        $now = $this->clock->now();
        $backedUp = $record->backupStatus === true;
        $this->credentials->recordUse($stored->credentialId, $record->counter, $backedUp, $now);

        return new AuthenticationResult($stored->userId, new StoredPasskey(
            $stored->credentialId, $stored->userId, $stored->userHandle, $stored->publicKey, $record->counter,
            $stored->transports, $stored->aaguid, $stored->backupEligible, $backedUp, $stored->attestationType,
            $stored->name, $stored->createdAt, $now,
        ));
    }

    /** @return list<StoredPasskey> */
    public function passkeys(string $userId): array
    {
        return $this->credentials->forUser($userId);
    }

    /** @param string $id The credential ID as the client knows it (base64url). */
    public function rename(string $userId, string $id, string $name): StoredPasskey
    {
        $credentialId = Base64Url::decode($id);
        $name = self::cleanName($name);
        if ($credentialId === null || ! $this->credentials->rename($userId, $credentialId, $name)) {
            throw PasskeyException::notFound();
        }
        $passkey = $this->credentials->find($credentialId);

        return $passkey ?? throw PasskeyException::notFound();
    }

    /** @param string $id The credential ID as the client knows it (base64url). */
    public function delete(string $userId, string $id): void
    {
        $credentialId = Base64Url::decode($id);
        if ($credentialId === null || ! $this->credentials->delete($userId, $credentialId)) {
            throw PasskeyException::notFound();
        }
    }

    private static function cleanName(string $name): string
    {
        $name = trim((string) preg_replace('/[\p{C}\s]+/u', ' ', $name));
        if ($name === '' || mb_strlen($name) > self::NAME_MAX) {
            throw PasskeyException::invalidRequest('A passkey name must be 1 to '.self::NAME_MAX.' characters.');
        }

        return $name;
    }

    /** @param array<string, mixed> $state */
    private function remember(array $state): string
    {
        $id = Base64Url::encode(random_bytes(32));
        $this->challenges->put(self::key($id), json_encode($state, JSON_THROW_ON_ERROR), $this->ceremonyTtlSeconds);

        return $id;
    }

    /** @return array<string, mixed> */
    private function recall(string $ceremonyId, string $purpose): array
    {
        $payload = $ceremonyId === '' ? null : $this->challenges->pull(self::key($ceremonyId));
        $state = $payload === null ? null : json_decode($payload, true);
        if (! is_array($state) || ($state['purpose'] ?? null) !== $purpose) {
            throw PasskeyException::ceremonyExpired();
        }

        /** @var array<string, mixed> $state */
        return $state;
    }

    /** The store never sees a ceremony ID, only its hash. */
    private static function key(string $ceremonyId): string
    {
        return 'ceremony:'.hash('sha256', $ceremonyId);
    }

    private static function bytes(mixed $text): string
    {
        $bytes = is_string($text) ? Base64Url::decode($text) : null;

        return $bytes ?? throw new InvalidArgumentException('Unreadable stored challenge.');
    }

    /** @return array{type: string, id: string, transports?: list<string>} */
    private static function descriptor(StoredPasskey $passkey): array
    {
        $descriptor = ['type' => 'public-key', 'id' => $passkey->id()];
        if ($passkey->transports !== []) {
            $descriptor['transports'] = $passkey->transports;
        }

        return $descriptor;
    }

    /**
     * @param  array<array-key, mixed>  $transports
     * @return list<string>
     */
    private static function transports(array $transports): array
    {
        $known = ['ble', 'cable', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb'];

        return array_values(array_unique(array_filter($transports, static fn (mixed $t): bool => in_array($t, $known, true))));
    }

    private static function record(StoredPasskey $passkey): CredentialRecord
    {
        return CredentialRecord::create(
            $passkey->credentialId,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $passkey->transports,
            $passkey->attestationType,
            EmptyTrustPath::create(),
            Uuid::fromString($passkey->aaguid),
            $passkey->publicKey,
            $passkey->userHandle,
            $passkey->counter,
            null,
            $passkey->backupEligible,
            $passkey->backedUp,
            true,
        );
    }

    /** @param array<array-key, mixed> $credential */
    private function parse(array $credential): PublicKeyCredential
    {
        $serializer = (new WebauthnSerializerFactory($this->attestations()))->create();
        if (! $serializer instanceof DenormalizerInterface) {
            throw new InvalidArgumentException('The WebAuthn serializer cannot denormalize.');
        }
        $public = $serializer->denormalize($credential, PublicKeyCredential::class, 'json');
        if (! $public instanceof PublicKeyCredential || $public->type !== 'public-key') {
            throw new InvalidArgumentException('Not a public-key credential.');
        }

        return $public;
    }

    private function attestations(): AttestationStatementSupportManager
    {
        return new AttestationStatementSupportManager([new NoneAttestationStatementSupport]);
    }

    private function steps(): CeremonyStepManagerFactory
    {
        $factory = new CeremonyStepManagerFactory;
        $factory->setAllowedOrigins($this->relyingParty->origins);
        $factory->setAlgorithmManager(Manager::create()->add(ES256::create(), RS256::create()));
        $factory->setAttestationStatementSupportManager($this->attestations());

        return $factory;
    }
}
