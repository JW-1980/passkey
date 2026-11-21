<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Tests\Laravel;

use Illuminate\Http\Request;
use Jw1980\Passkey\Firebase\FirebaseIdentity;
use Jw1980\Passkey\Firebase\IdTokenVerifier;
use Jw1980\Passkey\Firebase\Jwt;
use Jw1980\Passkey\Laravel\Http\Middleware\VerifyFirebaseToken;
use Jw1980\Passkey\Tests\Support\FirebaseKeys;
use Jw1980\Passkey\Tests\Support\SoftPasskey;

final class FirebaseModeTest extends TestCase
{
    private string $credentials;

    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);
        $this->credentials = (string) tempnam(sys_get_temp_dir(), 'sa');
        file_put_contents($this->credentials, FirebaseKeys::serviceAccountJson());
        $app['config']->set('passkey.firebase.enabled', true);
        $app['config']->set('passkey.firebase.project_id', FirebaseKeys::PROJECT);
        $app['config']->set('passkey.firebase.credentials', $this->credentials);
        $app['config']->set('passkey.firebase.check_user_exists', false);
        $app['config']->set('passkey.firebase.cors_origins', ['https://shop.example']);
        $app['config']->set('passkey.relying_party.related_origins', ['https://shop.example']);
        // Google's keys are the test's stand-in key.
        $app->singleton(IdTokenVerifier::class, static fn () => IdTokenVerifier::forProject(FirebaseKeys::PROJECT, new FirebaseKeys));
    }

    protected function defineRoutes($router): void
    {
        $router->post('/session', static function (Request $request) {
            $identity = $request->attributes->get(VerifyFirebaseToken::ATTRIBUTE);
            assert($identity instanceof FirebaseIdentity);

            return ['uid' => $identity->uid, 'method' => $identity->method()];
        })->middleware('firebase:mfa');
        $router->post('/typo', static fn () => ['ok' => true])->middleware('firebase:mfa, recnt=300');
    }

    public function test_an_unknown_middleware_option_refuses_instead_of_switching_a_check_off(): void
    {
        $this->postJson('/typo', [], $this->bearer(['login_method' => 'passkey', 'login_mfa' => true, 'firebase' => ['sign_in_provider' => 'custom']]))
            ->assertStatus(500)->assertJsonPath('error.code', 'configuration');
    }

    protected function tearDown(): void
    {
        @unlink($this->credentials);
        parent::tearDown();
    }

    /** @return array<string, string> */
    private function bearer(array $overrides = []): array
    {
        return ['Authorization' => 'Bearer '.FirebaseKeys::idToken(time(), $overrides)];
    }

    public function test_register_with_a_firebase_token_then_sign_in_for_a_custom_token(): void
    {
        $device = new SoftPasskey;
        $options = $this->postJson('/passkey/register/options', [], $this->bearer())->assertOk()->json();
        $this->postJson('/passkey/register/verify', [
            'ceremony' => $options['ceremony'],
            'credential' => $device->register($options['publicKey'], self::ORIGIN),
        ], $this->bearer())->assertCreated();

        $login = $this->postJson('/passkey/login/options')->assertOk()->json();
        $answer = $this->postJson('/passkey/login/verify', [
            'ceremony' => $login['ceremony'],
            'credential' => $device->assert($login['publicKey'], self::ORIGIN),
        ])->assertOk()->assertHeader('Cache-Control')->json();

        $token = Jwt::decode($answer['firebase']['customToken']);
        self::assertSame('firebase-uid-1', $token['payload']['uid']);
        self::assertSame('passkey', $token['payload']['claims']['login_method']);
        $this->assertGuest();
    }

    public function test_no_bearer_no_registration_and_no_session_routes(): void
    {
        $this->postJson('/passkey/register/options')->assertUnauthorized()->assertJsonPath('error.code', 'unauthenticated');
        $this->postJson('/passkey/register/options', [], $this->bearer(['auth_time' => time() - 3600, 'iat' => time() - 10]))
            ->assertForbidden()->assertJsonPath('error.code', 'reauthentication_required');
    }

    public function test_cors_and_related_origins(): void
    {
        $this->call('OPTIONS', '/passkey/login/options', [], [], [], ['HTTP_ORIGIN' => 'https://shop.example'])
            ->assertNoContent()->assertHeader('Access-Control-Allow-Origin', 'https://shop.example');
        $this->postJson('/passkey/login/options', [], ['Origin' => 'https://evil.example'])->assertForbidden();
        $this->getJson('/.well-known/webauthn')->assertOk()->assertExactJson(['origins' => [self::ORIGIN, 'https://shop.example']]);
    }

    public function test_middleware_requires_a_multi_factor_sign_in(): void
    {
        $this->postJson('/session')->assertUnauthorized();
        $this->postJson('/session', [], $this->bearer())->assertForbidden()->assertJsonPath('error.code', 'mfa_required');
        $this->postJson('/session', [], $this->bearer(['login_method' => 'passkey', 'login_mfa' => true, 'firebase' => ['sign_in_provider' => 'custom']]))
            ->assertOk()->assertExactJson(['uid' => 'firebase-uid-1', 'method' => 'passkey']);
    }

    public function test_handoff_is_available_in_firebase_mode(): void
    {
        $redirect = $this->postJson('/passkey/handoff/authorize', [
            'challenge' => 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', 'port' => 50000, 'state' => str_repeat('s', 43),
        ], $this->bearer())->assertOk()->json('redirect');
        parse_str((string) parse_url((string) $redirect, PHP_URL_QUERY), $query);
        $this->postJson('/passkey/handoff/exchange', ['code' => $query['code'], 'code_verifier' => 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'])
            ->assertOk()->assertJsonStructure(['firebase' => ['customToken', 'expiresIn']]);
    }
}
