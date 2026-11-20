<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Tests\Laravel;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Jw1980\Passkey\Handoff\HandoffGrant;
use Jw1980\Passkey\Laravel\Contracts\CompletesHandoff;
use Jw1980\Passkey\PasskeyException;
use Jw1980\Passkey\Tests\Support\SoftPasskey;
use Jw1980\Passkey\WellKnown;

/** An application with a table prefix, native apps and the desktop handoff switched on. */
final class ConfiguredAppTest extends TestCase
{
    private const FINGERPRINT = 'FA:C6:17:45:DC:09:03:78:6F:B9:ED:E6:2A:96:2B:39:9F:73:48:F0:BB:6F:89:9B:83:32:66:75:91:03:3B:9C';

    private const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    private const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    private const STATE = 'c3RhdGUtb2YtNDMtY2hhcmFjdGVycy1iYXNlNjR1cmw';

    protected static function tablePrefix(): string
    {
        return 'px_';
    }

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $app['config']->set('passkey.android', ['package' => 'nl.example.app', 'fingerprints' => [self::FINGERPRINT]]);
        $app['config']->set('passkey.apple.app_ids', ['A1B2C3D4E5.nl.example.app']);
        $app['config']->set('passkey.handoff.enabled', true);
        $app['config']->set('passkey.handoff.completer', TestHandoff::class);
    }

    public function test_the_stores_use_the_prefixed_tables(): void
    {
        $user = $this->user();
        $device = $this->enroll($user);
        $this->signOut();

        $this->signIn($device)->assertOk();
        $this->assertAuthenticatedAs($user);
        self::assertSame(1, (int) $this->app['db']->connection()->getPdo()->query('SELECT COUNT(*) FROM px_passkeys')->fetchColumn());
    }

    public function test_the_android_app_origin_is_allowed_and_its_association_is_served(): void
    {
        $this->getJson('/.well-known/assetlinks.json')->assertOk()
            ->assertJsonPath('0.target.package_name', 'nl.example.app')
            ->assertJsonPath('0.target.sha256_cert_fingerprints.0', self::FINGERPRINT)
            ->assertJsonPath('0.relation.1', 'delegate_permission/common.get_login_creds');
        $this->getJson('/.well-known/apple-app-site-association')->assertOk()
            ->assertExactJson(['webcredentials' => ['apps' => ['A1B2C3D4E5.nl.example.app']]]);

        $user = $this->user();
        $device = new SoftPasskey;
        $origin = WellKnown::androidOrigin(self::FINGERPRINT);
        $options = $this->actingAs($user)->postJson('/passkey/register/options')->json();
        $this->actingAs($user)->postJson('/passkey/register/verify', [
            'ceremony' => $options['ceremony'],
            'credential' => $device->register($options['publicKey'], $origin),
        ])->assertCreated();
    }

    public function test_the_desktop_handoff_issues_a_code_and_redeems_it_once(): void
    {
        $user = $this->user();

        $redirect = $this->actingAs($user)
            ->postJson('/passkey/handoff/authorize', ['challenge' => self::CHALLENGE, 'port' => 51234, 'state' => self::STATE])
            ->assertOk()->json('redirect');
        self::assertStringStartsWith('http://127.0.0.1:51234/callback?code=', $redirect);
        parse_str((string) parse_url($redirect, PHP_URL_QUERY), $query);
        self::assertSame(self::STATE, $query['state']);
        $this->signOut();

        // The desktop app has no session: the code and the verifier are all it presents.
        $this->postJson('/passkey/handoff/exchange', ['code' => $query['code'], 'code_verifier' => self::VERIFIER])
            ->assertOk()
            ->assertHeader('Cache-Control', 'no-store, private')
            ->assertExactJson(['token' => "desktop-session-of-{$user->id}", 'approvedBy' => 'ada@example.com']);

        $this->postJson('/passkey/handoff/exchange', ['code' => $query['code'], 'code_verifier' => self::VERIFIER])
            ->assertStatus(400)->assertJsonPath('error.code', 'invalid_handoff');
    }

    public function test_a_code_is_worthless_without_the_verifier(): void
    {
        $redirect = $this->actingAs($this->user())
            ->postJson('/passkey/handoff/authorize', ['challenge' => self::CHALLENGE, 'port' => 51234, 'state' => self::STATE])
            ->json('redirect');
        parse_str((string) parse_url($redirect, PHP_URL_QUERY), $query);

        $this->postJson('/passkey/handoff/exchange', ['code' => $query['code'], 'code_verifier' => str_repeat('a', 43)])->assertStatus(400);
        $this->postJson('/passkey/handoff/exchange', ['code' => $query['code']])->assertStatus(400);
        $this->postJson('/passkey/handoff/exchange', ['code' => $query['code'], 'code_verifier' => self::VERIFIER])->assertStatus(400);
    }

    public function test_a_guest_gets_no_handoff_code(): void
    {
        $this->postJson('/passkey/handoff/authorize', ['challenge' => self::CHALLENGE, 'port' => 51234, 'state' => self::STATE])
            ->assertUnauthorized();
        $this->assertDatabaseCount('passkey_challenges', 0);
    }

    public function test_the_application_can_refuse_to_hand_over_and_bad_requests_get_no_code(): void
    {
        $blocked = $this->user('Blocked');
        $this->actingAs($blocked)
            ->postJson('/passkey/handoff/authorize', ['challenge' => self::CHALLENGE, 'port' => 51234, 'state' => self::STATE])
            ->assertStatus(401);

        $user = $this->user();
        foreach ([
            ['challenge' => self::CHALLENGE, 'port' => '51234', 'state' => self::STATE],
            ['challenge' => self::CHALLENGE, 'port' => 80, 'state' => self::STATE],
            ['challenge' => 'short', 'port' => 51234, 'state' => self::STATE],
            ['challenge' => self::CHALLENGE, 'port' => 51234],
        ] as $body) {
            $this->actingAs($user)->postJson('/passkey/handoff/authorize', $body)->assertStatus(422);
        }
        $this->assertDatabaseCount('passkey_challenges', 0);
    }
}

final class TestHandoff implements CompletesHandoff
{
    public function approve(Request $request, Authenticatable $user): array
    {
        if ($user->name === 'Blocked') {
            throw PasskeyException::invalidPasskey();
        }

        return ['approvedBy' => $user->email];
    }

    public function complete(Request $request, HandoffGrant $grant): array
    {
        return ['token' => "desktop-session-of-{$grant->userId}", 'approvedBy' => $grant->context['approvedBy']];
    }
}
