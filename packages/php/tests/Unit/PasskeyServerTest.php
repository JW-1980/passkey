<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Tests\Unit;

use InvalidArgumentException;
use Jw1980\Passkey\Base64Url;
use Jw1980\Passkey\PasskeyException;
use Jw1980\Passkey\PasskeyServer;
use Jw1980\Passkey\RelyingParty;
use Jw1980\Passkey\Tests\Support\Fixture;
use Jw1980\Passkey\Tests\Support\SoftPasskey;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class PasskeyServerTest extends TestCase
{
    private Fixture $fixture;

    private PasskeyServer $server;

    protected function setUp(): void
    {
        $this->fixture = new Fixture;
        $this->server = $this->fixture->server;
    }

    private function refused(string $code, callable $action): PasskeyException
    {
        try {
            $action();
        } catch (PasskeyException $refusal) {
            self::assertSame($code, $refusal->errorCode);

            return $refusal;
        }
        self::fail("Expected the refusal '{$code}'.");
    }

    public function test_registration_options_fix_the_policy(): void
    {
        $options = $this->server->beginRegistration(Fixture::user())->publicKey;

        self::assertSame(['id' => 'app.example', 'name' => 'Example App'], $options['rp']);
        self::assertSame('user-1@example.com', $options['user']['name']);
        self::assertSame(
            ['residentKey' => 'required', 'requireResidentKey' => true, 'userVerification' => 'required'],
            $options['authenticatorSelection'],
        );
        self::assertSame('none', $options['attestation']);
        self::assertSame([['type' => 'public-key', 'alg' => -7], ['type' => 'public-key', 'alg' => -257]], $options['pubKeyCredParams']);
        self::assertSame(32, strlen((string) Base64Url::decode($options['challenge'])));
        self::assertSame([], $options['excludeCredentials']);
    }

    public function test_the_user_handle_is_opaque_stable_and_per_account(): void
    {
        $first = $this->server->beginRegistration(Fixture::user('user-1'))->publicKey['user']['id'];
        $again = $this->server->beginRegistration(Fixture::user('user-1'))->publicKey['user']['id'];
        $other = $this->server->beginRegistration(Fixture::user('user-2'))->publicKey['user']['id'];

        self::assertSame($first, $again);
        self::assertNotSame($first, $other);
        self::assertSame(32, strlen((string) Base64Url::decode($first)));
        self::assertStringNotContainsString('user-1', (string) Base64Url::decode($first));
    }

    public function test_every_ceremony_gets_its_own_challenge_and_id(): void
    {
        $a = $this->server->beginAuthentication();
        $b = $this->server->beginAuthentication();

        self::assertNotSame($a->id, $b->id);
        self::assertNotSame($a->publicKey['challenge'], $b->publicKey['challenge']);
    }

    public function test_a_registered_passkey_is_stored_with_its_properties(): void
    {
        $device = new SoftPasskey;
        $ceremony = $this->server->beginRegistration(Fixture::user());
        $passkey = $this->server->finishRegistration(
            $ceremony->id,
            $device->register($ceremony->publicKey, Fixture::ORIGIN, SoftPasskey::UP | SoftPasskey::UV | SoftPasskey::BE | SoftPasskey::BS),
            Fixture::user(),
            "  Work\tlaptop \n",
        );

        self::assertSame($device->credentialId, $passkey->credentialId);
        self::assertSame('Work laptop', $passkey->name);
        self::assertTrue($passkey->backupEligible);
        self::assertTrue($passkey->backedUp);
        self::assertSame(['internal', 'hybrid'], $passkey->transports);

        $stored = $this->server->passkeys('user-1');
        self::assertCount(1, $stored);
        self::assertSame([
            'id' => Base64Url::encode($device->credentialId),
            'name' => 'Work laptop',
            'createdAt' => '2026-11-20T10:00:00Z',
            'lastUsedAt' => null,
            'synced' => true,
            'transports' => ['internal', 'hybrid'],
        ], $stored[0]->toSummary());
        self::assertSame([], $this->server->passkeys('user-2'));
    }

    public function test_existing_passkeys_are_excluded_from_a_new_registration(): void
    {
        $device = $this->fixture->enroll();
        $options = $this->server->beginRegistration(Fixture::user())->publicKey;

        self::assertSame(
            [['type' => 'public-key', 'id' => Base64Url::encode($device->credentialId), 'transports' => ['internal', 'hybrid']]],
            $options['excludeCredentials'],
        );
    }

    public function test_a_ceremony_can_be_finished_only_once(): void
    {
        $device = new SoftPasskey;
        $ceremony = $this->server->beginRegistration(Fixture::user());
        $response = $device->register($ceremony->publicKey, Fixture::ORIGIN);
        $this->server->finishRegistration($ceremony->id, $response, Fixture::user());

        $this->refused(PasskeyException::CEREMONY_EXPIRED, fn () => $this->server->finishRegistration($ceremony->id, $response, Fixture::user()));
        self::assertCount(1, $this->server->passkeys('user-1'));
    }

    public function test_a_ceremony_expires(): void
    {
        $device = new SoftPasskey;
        $ceremony = $this->server->beginRegistration(Fixture::user());
        $response = $device->register($ceremony->publicKey, Fixture::ORIGIN);

        $this->fixture->clock->sleep(300);

        $this->refused(PasskeyException::CEREMONY_EXPIRED, fn () => $this->server->finishRegistration($ceremony->id, $response, Fixture::user()));
        self::assertSame([], $this->server->passkeys('user-1'));
    }

    public function test_a_ceremony_is_still_valid_just_before_it_expires(): void
    {
        $device = new SoftPasskey;
        $ceremony = $this->server->beginRegistration(Fixture::user());
        $this->fixture->clock->sleep(299);

        $this->server->finishRegistration($ceremony->id, $device->register($ceremony->publicKey, Fixture::ORIGIN), Fixture::user());

        self::assertCount(1, $this->server->passkeys('user-1'));
    }

    public function test_another_account_cannot_finish_someone_elses_registration(): void
    {
        $device = new SoftPasskey;
        $ceremony = $this->server->beginRegistration(Fixture::user('user-1'));
        $response = $device->register($ceremony->publicKey, Fixture::ORIGIN);

        $this->refused(PasskeyException::CEREMONY_EXPIRED, fn () => $this->server->finishRegistration($ceremony->id, $response, Fixture::user('user-2')));
        self::assertSame([], $this->server->passkeys('user-1'));
        self::assertSame([], $this->server->passkeys('user-2'));
    }

    public function test_a_sign_in_ceremony_cannot_finish_a_registration_and_the_reverse(): void
    {
        $device = new SoftPasskey;
        $login = $this->server->beginAuthentication();
        $registration = $this->server->beginRegistration(Fixture::user());
        $response = $device->register($registration->publicKey, Fixture::ORIGIN);

        $this->refused(PasskeyException::CEREMONY_EXPIRED, fn () => $this->server->finishRegistration($login->id, $response, Fixture::user()));
        $this->refused(PasskeyException::CEREMONY_EXPIRED, fn () => $this->server->finishAuthentication($registration->id, $response));
    }

    /** @return array<string, array{callable(SoftPasskey, array<string, mixed>): array<string, mixed>}> */
    public static function badRegistrations(): array
    {
        return [
            'another origin' => [fn (SoftPasskey $d, array $o) => $d->register($o, 'https://evil.example')],
            'a subdomain that is not allowed' => [fn (SoftPasskey $d, array $o) => $d->register($o, 'https://sub.app.example')],
            'http instead of https' => [fn (SoftPasskey $d, array $o) => $d->register($o, 'http://app.example')],
            'another port' => [fn (SoftPasskey $d, array $o) => $d->register($o, 'https://app.example:8443')],
            'no user verification' => [fn (SoftPasskey $d, array $o) => $d->register($o, Fixture::ORIGIN, SoftPasskey::UP)],
            'no user presence' => [fn (SoftPasskey $d, array $o) => $d->register($o, Fixture::ORIGIN, SoftPasskey::UV)],
            'another challenge' => [fn (SoftPasskey $d, array $o) => $d->register(['challenge' => Base64Url::encode(random_bytes(32))] + $o, Fixture::ORIGIN)],
            'another relying party' => [fn (SoftPasskey $d, array $o) => $d->register(['rp' => ['id' => 'evil.example']] + $o, Fixture::ORIGIN)],
            'a sign-in client data type' => [fn (SoftPasskey $d, array $o) => $d->register($o, Fixture::ORIGIN, type: 'webauthn.get')],
            'an assertion instead of an attestation' => [fn (SoftPasskey $d, array $o) => $d->assert(['rpId' => 'app.example'] + $o, Fixture::ORIGIN)],
            'no response' => [fn (SoftPasskey $d, array $o) => ['id' => 'x', 'rawId' => 'x', 'type' => 'public-key']],
            'an empty object' => [fn (SoftPasskey $d, array $o) => []],
            'garbage in the attestation' => [function (SoftPasskey $d, array $o) {
                $r = $d->register($o, Fixture::ORIGIN);
                $r['response']['attestationObject'] = Base64Url::encode('not cbor');

                return $r;
            }],
        ];
    }

    #[DataProvider('badRegistrations')]
    public function test_an_invalid_registration_is_refused_and_stores_nothing(callable $respond): void
    {
        $ceremony = $this->server->beginRegistration(Fixture::user());

        $refusal = $this->refused(
            PasskeyException::INVALID_REGISTRATION,
            fn () => $this->server->finishRegistration($ceremony->id, $respond(new SoftPasskey, $ceremony->publicKey), Fixture::user()),
        );

        self::assertSame(400, $refusal->httpStatus);
        self::assertSame('This passkey could not be registered.', $refusal->getMessage());
        self::assertSame([], $this->server->passkeys('user-1'));
    }

    public function test_the_same_credential_cannot_be_registered_twice(): void
    {
        $device = $this->fixture->enroll('user-1');
        $ceremony = $this->server->beginRegistration(Fixture::user('user-2'));

        $this->refused(
            PasskeyException::ALREADY_REGISTERED,
            fn () => $this->server->finishRegistration($ceremony->id, $device->register($ceremony->publicKey, Fixture::ORIGIN), Fixture::user('user-2')),
        );
        self::assertSame([], $this->server->passkeys('user-2'));
    }

    public function test_the_passkey_limit_holds_when_starting_and_when_finishing(): void
    {
        $fixture = new Fixture(maxPasskeys: 2);
        $fixture->enroll();
        $pending = $fixture->server->beginRegistration(Fixture::user());
        $fixture->enroll();

        $this->refused(PasskeyException::TOO_MANY_PASSKEYS, fn () => $fixture->server->beginRegistration(Fixture::user()));
        $this->refused(
            PasskeyException::TOO_MANY_PASSKEYS,
            fn () => $fixture->server->finishRegistration($pending->id, (new SoftPasskey)->register($pending->publicKey, Fixture::ORIGIN), Fixture::user()),
        );
        self::assertCount(2, $fixture->server->passkeys('user-1'));
        // The limit is per account.
        $fixture->enroll('user-2');
    }

    public function test_a_passkey_name_must_be_usable(): void
    {
        foreach (['', "  \n ", str_repeat('n', 101)] as $name) {
            $ceremony = $this->server->beginRegistration(Fixture::user());
            $response = (new SoftPasskey)->register($ceremony->publicKey, Fixture::ORIGIN);
            $this->refused(PasskeyException::INVALID_REQUEST, fn () => $this->server->finishRegistration($ceremony->id, $response, Fixture::user(), $name));
        }
        self::assertSame([], $this->server->passkeys('user-1'));
    }

    public function test_sign_in_options_ask_for_any_discoverable_passkey_with_user_verification(): void
    {
        $this->fixture->enroll();
        $options = $this->server->beginAuthentication()->publicKey;

        self::assertSame('app.example', $options['rpId']);
        self::assertSame([], $options['allowCredentials']);
        self::assertSame('required', $options['userVerification']);
        self::assertSame(300000, $options['timeout']);
    }

    public function test_a_discoverable_sign_in_identifies_the_account_and_records_the_use(): void
    {
        $this->fixture->enroll('user-1');
        $device = $this->fixture->enroll('user-2', SoftPasskey::UP | SoftPasskey::UV | SoftPasskey::BE);
        $this->fixture->clock->sleep(3600);

        $ceremony = $this->server->beginAuthentication();
        $result = $this->server->finishAuthentication(
            $ceremony->id,
            $device->assert($ceremony->publicKey, Fixture::ORIGIN, SoftPasskey::UP | SoftPasskey::UV | SoftPasskey::BE | SoftPasskey::BS),
        );

        self::assertSame('user-2', $result->userId);
        self::assertSame(1, $result->passkey->counter);
        self::assertTrue($result->passkey->backedUp);

        $stored = $this->server->passkeys('user-2')[0];
        self::assertSame(1, $stored->counter);
        self::assertTrue($stored->backedUp);
        self::assertSame('2026-11-20T11:00:00Z', $stored->toSummary()['lastUsedAt']);
        self::assertNull($this->server->passkeys('user-1')[0]->lastUsedAt);
    }

    public function test_a_sign_in_ceremony_can_be_finished_only_once(): void
    {
        $device = $this->fixture->enroll();
        $ceremony = $this->server->beginAuthentication();
        $response = $device->assert($ceremony->publicKey, Fixture::ORIGIN);
        $this->server->finishAuthentication($ceremony->id, $response);

        $this->refused(PasskeyException::CEREMONY_EXPIRED, fn () => $this->server->finishAuthentication($ceremony->id, $response));
    }

    public function test_a_response_cannot_be_replayed_on_a_new_ceremony(): void
    {
        $device = $this->fixture->enroll();
        $first = $this->server->beginAuthentication();
        $response = $device->assert($first->publicKey, Fixture::ORIGIN);
        $this->server->finishAuthentication($first->id, $response);

        $second = $this->server->beginAuthentication();
        $this->refused(PasskeyException::INVALID_PASSKEY, fn () => $this->server->finishAuthentication($second->id, $response));
    }

    /** @return array<string, array{callable(SoftPasskey, array<string, mixed>): array<string, mixed>}> */
    public static function badAssertions(): array
    {
        return [
            'another origin' => [fn (SoftPasskey $d, array $o) => $d->assert($o, 'https://evil.example')],
            'no user verification' => [fn (SoftPasskey $d, array $o) => $d->assert($o, Fixture::ORIGIN, SoftPasskey::UP)],
            'no user presence' => [fn (SoftPasskey $d, array $o) => $d->assert($o, Fixture::ORIGIN, SoftPasskey::UV)],
            'another challenge' => [fn (SoftPasskey $d, array $o) => $d->assert(['challenge' => Base64Url::encode(random_bytes(32))] + $o, Fixture::ORIGIN)],
            'another relying party' => [fn (SoftPasskey $d, array $o) => $d->assert($o, Fixture::ORIGIN, rpId: 'evil.example')],
            'a registration client data type' => [fn (SoftPasskey $d, array $o) => $d->assert($o, Fixture::ORIGIN, type: 'webauthn.create')],
            'no user handle' => [fn (SoftPasskey $d, array $o) => $d->assert($o, Fixture::ORIGIN, sendUserHandle: false)],
            'the user handle of another account' => [function (SoftPasskey $d, array $o) {
                $d->userHandle = hash_hmac('sha256', "passkey-user-handle\0user-2", Fixture::SECRET, true);

                return $d->assert($o, Fixture::ORIGIN);
            }],
            'a tampered signature' => [function (SoftPasskey $d, array $o) {
                $r = $d->assert($o, Fixture::ORIGIN);
                $signature = (string) Base64Url::decode($r['response']['signature']);
                $signature[strlen($signature) - 1] = chr(ord($signature[strlen($signature) - 1]) ^ 0x01);
                $r['response']['signature'] = Base64Url::encode($signature);

                return $r;
            }],
            'tampered authenticator data' => [function (SoftPasskey $d, array $o) {
                $r = $d->assert($o, Fixture::ORIGIN);
                $data = (string) Base64Url::decode($r['response']['authenticatorData']);
                $r['response']['authenticatorData'] = Base64Url::encode(substr($data, 0, 33).pack('N', 99));

                return $r;
            }],
            'the key of another authenticator' => [function (SoftPasskey $d, array $o) {
                $impostor = new SoftPasskey($d->credentialId);
                $impostor->userHandle = $d->userHandle;

                return $impostor->assert($o, Fixture::ORIGIN);
            }],
            'an unknown credential' => [function (SoftPasskey $d, array $o) {
                $stranger = new SoftPasskey;
                $stranger->userHandle = $d->userHandle;

                return $stranger->assert($o, Fixture::ORIGIN);
            }],
            'a registration instead of an assertion' => [fn (SoftPasskey $d, array $o) => $d->register(
                $o + ['user' => ['id' => Base64Url::encode('u')], 'rp' => ['id' => 'app.example']],
                Fixture::ORIGIN,
            )],
            'an empty object' => [fn (SoftPasskey $d, array $o) => []],
        ];
    }

    #[DataProvider('badAssertions')]
    public function test_an_invalid_sign_in_is_refused_with_one_message_and_changes_nothing(callable $respond): void
    {
        $this->fixture->enroll('user-2');
        $device = $this->fixture->enroll('user-1');
        $ceremony = $this->server->beginAuthentication();

        $refusal = $this->refused(
            PasskeyException::INVALID_PASSKEY,
            fn () => $this->server->finishAuthentication($ceremony->id, $respond($device, $ceremony->publicKey)),
        );

        self::assertSame(401, $refusal->httpStatus);
        self::assertSame('This passkey is not valid.', $refusal->getMessage());
        $stored = $this->server->passkeys('user-1')[0];
        self::assertSame(0, $stored->counter);
        self::assertNull($stored->lastUsedAt);
    }

    public function test_a_counter_that_does_not_increase_reveals_a_cloned_authenticator(): void
    {
        $device = $this->fixture->enroll();
        $first = $this->server->beginAuthentication();
        $this->server->finishAuthentication($first->id, $device->assert($first->publicKey, Fixture::ORIGIN));

        // The clone still has the counter of before that sign-in.
        $device->counter = 0;
        $second = $this->server->beginAuthentication();
        $this->refused(PasskeyException::INVALID_PASSKEY, fn () => $this->server->finishAuthentication($second->id, $device->assert($second->publicKey, Fixture::ORIGIN)));
        self::assertSame(1, $this->server->passkeys('user-1')[0]->counter);
    }

    public function test_reconfirming_an_account_accepts_only_its_own_passkeys(): void
    {
        $own = $this->fixture->enroll('user-1');
        $other = $this->fixture->enroll('user-2');

        $ceremony = $this->server->beginAuthentication('user-1');
        self::assertSame(
            [['type' => 'public-key', 'id' => Base64Url::encode($own->credentialId), 'transports' => ['internal', 'hybrid']]],
            $ceremony->publicKey['allowCredentials'],
        );
        $this->refused(PasskeyException::INVALID_PASSKEY, fn () => $this->server->finishAuthentication($ceremony->id, $other->assert($ceremony->publicKey, Fixture::ORIGIN)));

        $again = $this->server->beginAuthentication('user-1');
        // A non-discoverable flow may leave the user handle out; the account is already known.
        $result = $this->server->finishAuthentication($again->id, $own->assert($again->publicKey, Fixture::ORIGIN, sendUserHandle: false));
        self::assertSame('user-1', $result->userId);
    }

    public function test_reconfirming_an_account_without_passkeys_is_refused(): void
    {
        $this->refused(PasskeyException::INVALID_PASSKEY, fn () => $this->server->beginAuthentication('nobody'));
    }

    public function test_an_android_app_origin_is_accepted_only_when_listed(): void
    {
        $android = 'android:apk-key-hash:'.Base64Url::encode(hash('sha256', 'certificate', true));
        $fixture = new Fixture([Fixture::ORIGIN, $android]);
        $device = new SoftPasskey;

        $ceremony = $fixture->server->beginRegistration(Fixture::user());
        $fixture->server->finishRegistration($ceremony->id, $device->register($ceremony->publicKey, $android), Fixture::user());
        $login = $fixture->server->beginAuthentication();
        self::assertSame('user-1', $fixture->server->finishAuthentication($login->id, $device->assert($login->publicKey, $android))->userId);

        $unlisted = $this->server->beginRegistration(Fixture::user());
        $this->refused(
            PasskeyException::INVALID_REGISTRATION,
            fn () => $this->server->finishRegistration($unlisted->id, (new SoftPasskey)->register($unlisted->publicKey, $android), Fixture::user()),
        );
    }

    public function test_renaming_and_deleting_are_limited_to_the_owner(): void
    {
        $device = $this->fixture->enroll('user-1');
        $id = Base64Url::encode($device->credentialId);

        $this->refused(PasskeyException::NOT_FOUND, fn () => $this->server->rename('user-2', $id, 'Mine now'));
        $this->refused(PasskeyException::NOT_FOUND, fn () => $this->server->delete('user-2', $id));
        $this->refused(PasskeyException::NOT_FOUND, fn () => $this->server->delete('user-1', 'not base64url!'));
        $this->refused(PasskeyException::INVALID_REQUEST, fn () => $this->server->rename('user-1', $id, ''));

        self::assertSame('Phone', $this->server->rename('user-1', $id, 'Phone')->name);
        // Renaming to the same name is not "not found".
        self::assertSame('Phone', $this->server->rename('user-1', $id, 'Phone')->name);

        $this->server->delete('user-1', $id);
        self::assertSame([], $this->server->passkeys('user-1'));
        $this->refused(PasskeyException::NOT_FOUND, fn () => $this->server->delete('user-1', $id));
    }

    public function test_a_deleted_passkey_no_longer_signs_in(): void
    {
        $device = $this->fixture->enroll();
        $this->server->delete('user-1', Base64Url::encode($device->credentialId));

        $ceremony = $this->server->beginAuthentication();
        $this->refused(PasskeyException::INVALID_PASSKEY, fn () => $this->server->finishAuthentication($ceremony->id, $device->assert($ceremony->publicKey, Fixture::ORIGIN)));
    }

    public function test_the_server_refuses_a_weak_configuration(): void
    {
        $party = new RelyingParty('app.example', 'Example App', [Fixture::ORIGIN]);
        foreach ([['short', 300, 10], [Fixture::SECRET, 29, 10], [Fixture::SECRET, 3601, 10], [Fixture::SECRET, 300, 0]] as [$secret, $ttl, $max]) {
            try {
                new PasskeyServer($party, $this->fixture->credentials, $this->fixture->challenges, $secret, $ttl, $max);
                self::fail('Expected a refusal.');
            } catch (InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }
}
