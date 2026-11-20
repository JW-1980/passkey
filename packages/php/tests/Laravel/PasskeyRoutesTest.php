<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Tests\Laravel;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Event;
use Jw1980\Passkey\AuthenticationResult;
use Jw1980\Passkey\Base64Url;
use Jw1980\Passkey\Laravel\Contracts\CompletesLogin;
use Jw1980\Passkey\Laravel\Events\PasskeyAuthenticated;
use Jw1980\Passkey\Laravel\Events\PasskeyDeleted;
use Jw1980\Passkey\Laravel\Events\PasskeyRegistered;
use Jw1980\Passkey\Laravel\Events\PasskeyRejected;
use Jw1980\Passkey\Laravel\SessionLogin;
use Jw1980\Passkey\Tests\Support\SoftPasskey;

final class PasskeyRoutesTest extends TestCase
{
    public function test_an_account_registers_a_passkey_and_signs_in_with_it(): void
    {
        Event::fake([PasskeyRegistered::class, PasskeyAuthenticated::class]);
        $user = $this->user();
        $this->user('Grace');

        $device = $this->enroll($user, 'Laptop');
        Event::assertDispatched(PasskeyRegistered::class, fn (PasskeyRegistered $e): bool => $e->passkey->userId === (string) $user->id && $e->passkey->name === 'Laptop');
        $this->assertDatabaseHas('passkeys', ['user_id' => (string) $user->id, 'name' => 'Laptop', 'counter' => 0]);

        $this->signOut();
        $this->assertGuest();

        $this->signIn($device)->assertOk()->assertExactJson(['ok' => true]);

        $this->assertAuthenticatedAs($user);
        self::assertIsInt(session(SessionLogin::CONFIRMED_AT));
        Event::assertDispatched(PasskeyAuthenticated::class, fn (PasskeyAuthenticated $e): bool => $e->result->userId === (string) $user->id);
        $this->assertDatabaseHas('passkeys', ['user_id' => (string) $user->id, 'counter' => 1]);
    }

    public function test_registration_options_describe_the_signed_in_account_and_this_site(): void
    {
        $options = $this->actingAs($this->user())->postJson('/passkey/register/options')->assertOk()->json('publicKey');

        self::assertSame(['id' => 'app.example', 'name' => 'Example App'], $options['rp']);
        self::assertSame('ada@example.com', $options['user']['name']);
        self::assertSame('Ada', $options['user']['displayName']);
    }

    public function test_a_guest_cannot_register_or_manage_passkeys(): void
    {
        $this->postJson('/passkey/register/options')->assertUnauthorized();
        $this->postJson('/passkey/register/verify', ['ceremony' => 'x', 'credential' => []])->assertUnauthorized();
        $this->getJson('/passkey/passkeys')->assertUnauthorized();
        $this->patchJson('/passkey/passkeys/abc', ['name' => 'x'])->assertUnauthorized();
        $this->deleteJson('/passkey/passkeys/abc')->assertUnauthorized();
        $this->assertDatabaseCount('passkeys', 0);
        $this->assertDatabaseCount('passkey_challenges', 0);
    }

    public function test_an_invalid_sign_in_is_refused_and_leaves_the_visitor_a_guest(): void
    {
        Event::fake([PasskeyRejected::class, PasskeyAuthenticated::class]);
        $user = $this->user();
        $this->enroll($user);
        $this->signOut();

        $stranger = new SoftPasskey;
        $stranger->userHandle = random_bytes(32);
        $this->signIn($stranger)
            ->assertUnauthorized()
            ->assertExactJson(['error' => ['code' => 'invalid_passkey', 'message' => 'This passkey is not valid.']]);

        $this->assertGuest();
        Event::assertNotDispatched(PasskeyAuthenticated::class);
        Event::assertDispatched(PasskeyRejected::class, fn (PasskeyRejected $e): bool => $e->refusal->errorCode === 'invalid_passkey' && $e->userId === null && $e->refusal->getPrevious() !== null);
    }

    public function test_a_sign_in_from_another_origin_is_refused(): void
    {
        $device = $this->enroll($this->user());
        $this->signOut();

        $options = $this->postJson('/passkey/login/options')->json();
        $this->postJson('/passkey/login/verify', [
            'ceremony' => $options['ceremony'],
            'credential' => $device->assert($options['publicKey'], 'https://phishing.example'),
        ])->assertUnauthorized();
        $this->assertGuest();
    }

    public function test_a_passkey_of_a_removed_account_no_longer_signs_in(): void
    {
        $user = $this->user();
        $device = $this->enroll($user);
        $this->signOut();
        $user->delete();

        $this->signIn($device)->assertUnauthorized()->assertJsonPath('error.code', 'invalid_passkey');
        $this->assertGuest();
    }

    public function test_incomplete_requests_are_refused(): void
    {
        $user = $this->user();

        $this->postJson('/passkey/login/verify', [])->assertStatus(422)->assertJsonPath('error.code', 'invalid_request');
        $this->postJson('/passkey/login/verify', ['ceremony' => 'x', 'credential' => 'text'])->assertStatus(422);
        $this->postJson('/passkey/login/verify', ['ceremony' => ['x'], 'credential' => []])->assertStatus(422);
        $this->postJson('/passkey/login/verify', ['ceremony' => 'unknown', 'credential' => []])->assertStatus(400)->assertJsonPath('error.code', 'ceremony_expired');
        $this->actingAs($user)->postJson('/passkey/register/verify', ['ceremony' => 'x', 'credential' => [], 'name' => ['a']])->assertStatus(422);
        $this->assertDatabaseCount('passkeys', 0);
    }

    public function test_someone_signed_in_can_only_confirm_with_their_own_passkey(): void
    {
        $ada = $this->user();
        $grace = $this->user('Grace');
        $adasDevice = $this->enroll($ada);
        $gracesDevice = $this->enroll($grace);

        $options = $this->actingAs($ada)->postJson('/passkey/login/options')->assertOk()->json();
        self::assertSame([Base64Url::encode($adasDevice->credentialId)], array_column($options['publicKey']['allowCredentials'], 'id'));
        $this->actingAs($ada)->postJson('/passkey/login/verify', [
            'ceremony' => $options['ceremony'],
            'credential' => $gracesDevice->assert($options['publicKey'], self::ORIGIN),
        ])->assertUnauthorized();
        $this->assertAuthenticatedAs($ada);

        $again = $this->actingAs($ada)->postJson('/passkey/login/options')->json();
        $this->actingAs($ada)->postJson('/passkey/login/verify', [
            'ceremony' => $again['ceremony'],
            'credential' => $adasDevice->assert($again['publicKey'], self::ORIGIN),
        ])->assertOk();
        $this->assertAuthenticatedAs($ada);
    }

    public function test_an_account_manages_only_its_own_passkeys(): void
    {
        Event::fake([PasskeyDeleted::class]);
        $ada = $this->user();
        $grace = $this->user('Grace');
        $adasId = Base64Url::encode($this->enroll($ada, 'Ada laptop')->credentialId);
        $gracesId = Base64Url::encode($this->enroll($grace, 'Grace phone')->credentialId);

        $this->actingAs($ada)->getJson('/passkey/passkeys')->assertOk()
            ->assertJsonCount(1, 'passkeys')
            ->assertJsonPath('passkeys.0.id', $adasId)
            ->assertJsonPath('passkeys.0.name', 'Ada laptop')
            ->assertJsonPath('passkeys.0.lastUsedAt', null)
            ->assertJsonMissingPath('passkeys.0.publicKey');

        $this->actingAs($ada)->patchJson("/passkey/passkeys/{$gracesId}", ['name' => 'Mine'])->assertNotFound()->assertJsonPath('error.code', 'not_found');
        $this->actingAs($ada)->deleteJson("/passkey/passkeys/{$gracesId}")->assertNotFound();
        $this->assertDatabaseHas('passkeys', ['user_id' => (string) $grace->id, 'name' => 'Grace phone']);
        Event::assertNotDispatched(PasskeyDeleted::class);

        $this->actingAs($ada)->patchJson("/passkey/passkeys/{$adasId}", ['name' => 'Work'])->assertOk()->assertJsonPath('passkey.name', 'Work');
        $this->actingAs($ada)->patchJson("/passkey/passkeys/{$adasId}", ['name' => ''])->assertStatus(422);
        $this->actingAs($ada)->patchJson("/passkey/passkeys/{$adasId}", [])->assertStatus(422);
        $this->actingAs($ada)->deleteJson("/passkey/passkeys/{$adasId}")->assertNoContent();
        $this->assertDatabaseMissing('passkeys', ['user_id' => (string) $ada->id]);
        Event::assertDispatched(PasskeyDeleted::class, fn (PasskeyDeleted $e): bool => $e->userId === (string) $ada->id && $e->passkeyId === $adasId);
    }

    public function test_the_routes_are_rate_limited_per_address(): void
    {
        config(['passkey.rate_limit' => 2]);

        $this->postJson('/passkey/login/options')->assertOk();
        $this->postJson('/passkey/login/options')->assertOk();
        $this->postJson('/passkey/login/options')->assertStatus(429);
        $this->withServerVariables(['REMOTE_ADDR' => '203.0.113.9'])->postJson('/passkey/login/options')->assertOk();
    }

    public function test_the_application_can_replace_what_a_sign_in_leads_to(): void
    {
        $this->app->bind(CompletesLogin::class, fn () => new class implements CompletesLogin
        {
            public function complete(Request $request, AuthenticationResult $result): array
            {
                return ['next' => 'second_factor', 'account' => $result->userId];
            }
        });
        $user = $this->user();
        $device = $this->enroll($user);
        $this->signOut();

        $this->signIn($device)->assertOk()->assertExactJson(['next' => 'second_factor', 'account' => (string) $user->id]);
        $this->assertGuest();
    }

    public function test_association_files_are_not_served_without_configuration(): void
    {
        $this->getJson('/.well-known/assetlinks.json')->assertNotFound();
        $this->getJson('/.well-known/apple-app-site-association')->assertNotFound();
        $this->postJson('/passkey/handoff/exchange', [])->assertNotFound();
    }
}
