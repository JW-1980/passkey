<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Tests\Firebase;

use Jw1980\Passkey\Firebase\AdminClient;
use Jw1980\Passkey\Firebase\CustomTokenIssuer;
use Jw1980\Passkey\Firebase\FirebasePasskeys;
use Jw1980\Passkey\Firebase\Http\AuthHub;
use Jw1980\Passkey\Firebase\Http\HubRequest;
use Jw1980\Passkey\Firebase\Http\HubResponse;
use Jw1980\Passkey\Firebase\HttpResponse;
use Jw1980\Passkey\Firebase\IdTokenVerifier;
use Jw1980\Passkey\Firebase\Jwt;
use Jw1980\Passkey\Handoff\HandoffServer;
use Jw1980\Passkey\Storage\PdoRateLimiter;
use Jw1980\Passkey\Tests\Support\FakeHttp;
use Jw1980\Passkey\Tests\Support\FirebaseKeys;
use Jw1980\Passkey\Tests\Support\Fixture;
use Jw1980\Passkey\Tests\Support\SoftPasskey;
use PHPUnit\Framework\TestCase;

final class AuthHubTest extends TestCase
{
    private const WEB = 'https://shop.example';

    private const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    private const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    private const STATE = 'c3RhdGUtb2YtNDMtY2hhcmFjdGVycy1iYXNlNjR1cmw';

    private Fixture $fixture;

    private AuthHub $hub;

    /** @var list<array{int, string}> Answers of the fake Identity Toolkit. */
    private array $toolkit = [];

    private function makeHub(bool $withAdmin = false, int $limit = 30): AuthHub
    {
        $admin = null;
        if ($withAdmin) {
            $admin = AdminClient::forServiceAccount(FirebaseKeys::serviceAccount(), new FakeHttp(function (string $method, string $url) {
                if (str_contains($url, 'oauth2')) {
                    return new HttpResponse(200, [], '{"access_token":"t","expires_in":3600}');
                }
                [$status, $body] = array_shift($this->toolkit) ?? [200, '{}'];

                return new HttpResponse($status, [], $body);
            }), $this->fixture->clock);
        }
        $passkeys = new FirebasePasskeys(
            $this->fixture->server,
            new HandoffServer($this->fixture->challenges),
            new CustomTokenIssuer(FirebaseKeys::serviceAccount(), 300, $this->fixture->clock),
            IdTokenVerifier::forProject(FirebaseKeys::PROJECT, new FirebaseKeys, $this->fixture->clock),
            $admin,
        );
        foreach (PdoRateLimiter::statements('sqlite') as $statement) {
            $this->fixture->pdo->exec($statement);
        }

        return new AuthHub($passkeys, '/passkey', [self::WEB, Fixture::ORIGIN], new PdoRateLimiter($this->fixture->pdo, clock: $this->fixture->clock), $limit, [
            '/.well-known/webauthn' => ['origins' => [self::WEB]],
        ]);
    }

    protected function setUp(): void
    {
        $this->fixture = new Fixture;
        $this->hub = $this->makeHub();
    }

    private function now(): int
    {
        return $this->fixture->clock->now()->getTimestamp();
    }

    /** @param array<string, mixed> $overrides */
    private function idToken(array $overrides = []): string
    {
        return FirebaseKeys::idToken($this->now(), $overrides);
    }

    /**
     * @param  array<string, mixed>|null  $body
     * @param  array<string, string>  $headers
     */
    private function call(string $method, string $path, ?array $body = null, ?string $token = null, array $headers = [], string $ip = '203.0.113.5'): HubResponse
    {
        if ($token !== null) {
            $headers['Authorization'] = 'Bearer '.$token;
        }
        $response = $this->hub->handle(new HubRequest($method, $path, $headers, $body === null ? '' : (string) json_encode($body), $ip));
        self::assertNotNull($response, "{$method} {$path} was not handled");

        return $response;
    }

    /** @return array<string, mixed> */
    private static function json(HubResponse $response): array
    {
        $data = json_decode($response->body, true);
        self::assertIsArray($data, $response->body);

        return $data;
    }

    private function register(SoftPasskey $device, ?string $token = null): HubResponse
    {
        $token ??= $this->idToken();
        $options = self::json($this->call('POST', '/passkey/register/options', [], $token));

        return $this->call('POST', '/passkey/register/verify', [
            'ceremony' => $options['ceremony'],
            'credential' => $device->register($options['publicKey'], Fixture::ORIGIN),
            'name' => 'Laptop',
        ], $token);
    }

    private function signIn(SoftPasskey $device): HubResponse
    {
        $options = self::json($this->call('POST', '/passkey/login/options'));

        return $this->call('POST', '/passkey/login/verify', [
            'ceremony' => $options['ceremony'],
            'credential' => $device->assert($options['publicKey'], Fixture::ORIGIN),
        ]);
    }

    public function test_firebase_user_registers_a_passkey_and_signs_in_with_it_as_the_same_uid(): void
    {
        $device = new SoftPasskey;
        $registered = $this->register($device);
        self::assertSame(201, $registered->status, $registered->body);
        self::assertSame('Laptop', self::json($registered)['passkey']['name']);

        $signedIn = $this->signIn($device);
        self::assertSame(200, $signedIn->status, $signedIn->body);
        self::assertSame('no-store', $signedIn->headers['Cache-Control']);
        $answer = self::json($signedIn);
        self::assertSame(300, $answer['firebase']['expiresIn']);
        self::assertSame(['firebase'], array_keys($answer), 'the answer reveals nothing else');

        $token = Jwt::decode($answer['firebase']['customToken']);
        self::assertSame('firebase-uid-1', $token['payload']['uid']);
        self::assertSame(['login_method' => 'passkey', 'login_mfa' => true], $token['payload']['claims']);
        self::assertTrue(Jwt::verifyRs256($token['input'], $token['signature'], FirebaseKeys::pair('service-account')['public']));
    }

    public function test_the_passkey_prompt_shows_the_email_and_never_the_uid(): void
    {
        $options = self::json($this->call('POST', '/passkey/register/options', [], $this->idToken()));
        self::assertSame('ann@example.com', $options['publicKey']['user']['name']);
        self::assertStringNotContainsString('firebase-uid-1', (string) json_encode($options));
    }

    public function test_signed_in_routes_need_a_valid_bearer_token(): void
    {
        foreach ([
            ['POST', '/passkey/register/options'],
            ['POST', '/passkey/register/verify'],
            ['GET', '/passkey/passkeys'],
            ['PATCH', '/passkey/passkeys/AAAA'],
            ['DELETE', '/passkey/passkeys/AAAA'],
            ['POST', '/passkey/handoff/authorize'],
        ] as [$method, $path]) {
            $none = $this->call($method, $path, []);
            self::assertSame(401, $none->status, "{$method} {$path}");
            self::assertSame('unauthenticated', self::json($none)['error']['code']);
            self::assertSame('Bearer', $none->headers['WWW-Authenticate']);

            $forged = $this->call($method, $path, [], FirebaseKeys::idToken($this->now(), [], ['alg' => 'RS256', 'kid' => FirebaseKeys::KID], 'service-account'));
            self::assertSame(401, $forged->status, "{$method} {$path} with a forged token");

            $otherProject = $this->call($method, $path, [], $this->idToken(['aud' => 'other-project']));
            self::assertSame(401, $otherProject->status);
        }
    }

    public function test_token_in_the_query_string_or_cookie_is_ignored(): void
    {
        $token = $this->idToken();
        $response = $this->call('GET', '/passkey/passkeys?token='.$token, null, null, ['Cookie' => 'token='.$token]);
        self::assertSame(401, $response->status);
    }

    public function test_registering_needs_a_recent_sign_in(): void
    {
        $stale = $this->idToken(['auth_time' => $this->now() - 601]);
        $response = $this->call('POST', '/passkey/register/options', [], $stale);
        self::assertSame(403, $response->status);
        self::assertSame('reauthentication_required', self::json($response)['error']['code']);

        // A token refreshed a minute ago, but signed in long ago, is not recent either.
        $refreshed = $this->idToken(['auth_time' => $this->now() - 7200, 'iat' => $this->now() - 60]);
        self::assertSame(403, $this->call('POST', '/passkey/register/options', [], $refreshed)->status);
    }

    public function test_a_registration_cannot_be_finished_by_another_user(): void
    {
        $options = self::json($this->call('POST', '/passkey/register/options', [], $this->idToken()));
        $mallory = $this->idToken(['sub' => 'mallory', 'user_id' => 'mallory']);
        $response = $this->call('POST', '/passkey/register/verify', [
            'ceremony' => $options['ceremony'],
            'credential' => (new SoftPasskey)->register($options['publicKey'], Fixture::ORIGIN),
        ], $mallory);
        self::assertSame(400, $response->status);
        self::assertSame('ceremony_expired', self::json($response)['error']['code']);
    }

    public function test_listing_renaming_and_deleting_only_touch_own_passkeys(): void
    {
        $device = new SoftPasskey;
        $id = self::json($this->register($device))['passkey']['id'];
        $mallory = $this->idToken(['sub' => 'mallory', 'user_id' => 'mallory']);

        self::assertSame([], self::json($this->call('GET', '/passkey/passkeys', null, $mallory))['passkeys']);
        self::assertSame(404, $this->call('PATCH', "/passkey/passkeys/{$id}", ['name' => 'x'], $mallory)->status);
        self::assertSame(404, $this->call('DELETE', "/passkey/passkeys/{$id}", null, $mallory)->status);

        $list = self::json($this->call('GET', '/passkey/passkeys', null, $this->idToken()))['passkeys'];
        self::assertSame([$id], array_column($list, 'id'));
        self::assertSame('Phone', self::json($this->call('PATCH', "/passkey/passkeys/{$id}", ['name' => 'Phone'], $this->idToken()))['passkey']['name']);

        $stale = $this->idToken(['auth_time' => $this->now() - 3600]);
        self::assertSame(403, $this->call('DELETE', "/passkey/passkeys/{$id}", null, $stale)->status, 'delete needs a recent sign-in');
        self::assertSame(204, $this->call('DELETE', "/passkey/passkeys/{$id}", null, $this->idToken())->status);
        self::assertSame(401, $this->signIn($device)->status, 'a deleted passkey no longer signs in');
    }

    public function test_handoff_gives_the_desktop_a_custom_token_with_the_browser_method(): void
    {
        $authorize = $this->call('POST', '/passkey/handoff/authorize', ['challenge' => self::CHALLENGE, 'port' => 51234, 'state' => self::STATE], $this->idToken());
        self::assertSame(200, $authorize->status, $authorize->body);
        $redirect = (string) self::json($authorize)['redirect'];
        self::assertStringStartsWith('http://127.0.0.1:51234/callback?code=', $redirect);
        parse_str((string) parse_url($redirect, PHP_URL_QUERY), $query);

        $wrong = $this->call('POST', '/passkey/handoff/exchange', ['code' => $query['code'], 'code_verifier' => str_repeat('a', 43)]);
        self::assertSame(400, $wrong->status);
        self::assertSame(400, $this->call('POST', '/passkey/handoff/exchange', ['code' => $query['code'], 'code_verifier' => self::VERIFIER])->status, 'the code is spent after a failure');

        $authorize = $this->call('POST', '/passkey/handoff/authorize', ['challenge' => self::CHALLENGE, 'port' => 51234, 'state' => self::STATE], $this->idToken());
        parse_str((string) parse_url((string) self::json($authorize)['redirect'], PHP_URL_QUERY), $query);
        $exchange = $this->call('POST', '/passkey/handoff/exchange', ['code' => $query['code'], 'code_verifier' => self::VERIFIER]);
        self::assertSame(200, $exchange->status, $exchange->body);
        $token = Jwt::decode(self::json($exchange)['firebase']['customToken']);
        self::assertSame('firebase-uid-1', $token['payload']['uid']);
        self::assertSame(['login_method' => 'handoff', 'login_via' => 'password', 'login_mfa' => false, 'login_auth_time' => $this->now() - 30], $token['payload']['claims']);
    }

    public function test_handoff_from_a_passkey_session_stays_multi_factor(): void
    {
        $token = $this->idToken(['login_method' => 'passkey', 'login_mfa' => true, 'firebase' => ['sign_in_provider' => 'custom']]);
        $authorize = $this->call('POST', '/passkey/handoff/authorize', ['challenge' => self::CHALLENGE, 'port' => 51234, 'state' => self::STATE], $token);
        parse_str((string) parse_url((string) self::json($authorize)['redirect'], PHP_URL_QUERY), $query);
        $claims = Jwt::decode(self::json($this->call('POST', '/passkey/handoff/exchange', ['code' => $query['code'], 'code_verifier' => self::VERIFIER]))['firebase']['customToken'])['payload']['claims'];
        self::assertSame(['login_method' => 'handoff', 'login_via' => 'passkey', 'login_mfa' => true, 'login_auth_time' => $this->now() - 30], $claims);
    }

    public function test_a_handoff_keeps_the_browser_sign_in_time_so_recency_cannot_be_laundered(): void
    {
        // The browser signed in 500 s ago: recent enough to authorize, not much longer.
        $browser = $this->idToken(['auth_time' => $this->now() - 500]);
        $authorize = $this->call('POST', '/passkey/handoff/authorize', ['challenge' => self::CHALLENGE, 'port' => 51234, 'state' => self::STATE], $browser);
        parse_str((string) parse_url((string) self::json($authorize)['redirect'], PHP_URL_QUERY), $query);
        $claims = Jwt::decode(self::json($this->call('POST', '/passkey/handoff/exchange', ['code' => $query['code'], 'code_verifier' => self::VERIFIER]))['firebase']['customToken'])['payload']['claims'];
        self::assertSame($this->now() - 500, $claims['login_auth_time']);

        // Firebase would issue the app an ID token with auth_time = now and these claims.
        $this->fixture->clock->sleep(200);
        $appToken = $this->idToken(['auth_time' => $this->now(), 'firebase' => ['sign_in_provider' => 'custom']] + $claims);
        $again = $this->call('POST', '/passkey/handoff/authorize', ['challenge' => self::CHALLENGE, 'port' => 51234, 'state' => self::STATE], $appToken);
        self::assertSame(403, $again->status, 'the handed-off token is 700 s old in sign-in terms');
        self::assertSame(403, $this->call('POST', '/passkey/register/options', [], $appToken)->status);
    }

    public function test_handoff_needs_a_recent_sign_in(): void
    {
        $response = $this->call('POST', '/passkey/handoff/authorize', ['challenge' => self::CHALLENGE, 'port' => 51234, 'state' => self::STATE], $this->idToken(['auth_time' => $this->now() - 3600]));
        self::assertSame(403, $response->status);
    }

    public function test_cors_only_for_listed_origins_and_without_credentials(): void
    {
        $preflight = $this->call('OPTIONS', '/passkey/login/options', null, null, ['Origin' => self::WEB]);
        self::assertSame(204, $preflight->status);
        self::assertSame(self::WEB, $preflight->headers['Access-Control-Allow-Origin']);
        self::assertStringContainsString('Authorization', $preflight->headers['Access-Control-Allow-Headers']);
        self::assertArrayNotHasKey('Access-Control-Allow-Credentials', $preflight->headers);

        $allowed = $this->call('POST', '/passkey/login/options', null, null, ['Origin' => self::WEB]);
        self::assertSame(200, $allowed->status);
        self::assertSame(self::WEB, $allowed->headers['Access-Control-Allow-Origin']);
        self::assertSame('Origin', $allowed->headers['Vary']);

        $other = $this->call('POST', '/passkey/login/options', null, null, ['Origin' => 'https://evil.example']);
        self::assertSame(403, $other->status);
        self::assertSame('origin_not_allowed', self::json($other)['error']['code']);
        self::assertArrayNotHasKey('Access-Control-Allow-Origin', $other->headers);

        $native = $this->call('POST', '/passkey/login/options');
        self::assertSame(200, $native->status, 'apps send no Origin');
    }

    public function test_sign_in_routes_are_rate_limited_per_ip(): void
    {
        $this->hub = $this->makeHub(limit: 3);
        for ($i = 0; $i < 3; $i++) {
            self::assertSame(200, $this->call('POST', '/passkey/login/options')->status);
        }
        $limited = $this->call('POST', '/passkey/login/options');
        self::assertSame(429, $limited->status);
        self::assertSame('60', $limited->headers['Retry-After']);
        self::assertSame(200, $this->call('POST', '/passkey/login/options', ip: '198.51.100.7')->status, 'another IP is not limited');
        $this->fixture->clock->sleep(61);
        self::assertSame(200, $this->call('POST', '/passkey/login/options')->status, 'the next window is open again');
    }

    public function test_with_the_admin_client_a_deleted_firebase_user_cannot_sign_in_and_loses_its_passkeys(): void
    {
        $this->hub = $this->makeHub(withAdmin: true);
        $device = new SoftPasskey;
        $this->register($device);

        $this->toolkit = [[200, '{"users":[{"localId":"firebase-uid-1","disabled":true}]}']];
        self::assertSame(401, $this->signIn($device)->status, 'disabled');

        $this->toolkit = [[200, '{"users":[{"localId":"firebase-uid-1"}]}']];
        self::assertSame(200, $this->signIn($device)->status, 'enabled again');

        $this->toolkit = [[200, '{}']];
        self::assertSame(401, $this->signIn($device)->status, 'deleted');
        self::assertSame([], $this->fixture->server->passkeys('firebase-uid-1'));
    }

    public function test_bad_requests(): void
    {
        $response = $this->hub->handle(new HubRequest('POST', '/passkey/login/verify', [], '{not json', '1.2.3.4'));
        self::assertNotNull($response);
        self::assertSame(422, $response->status);
        self::assertSame(422, $this->call('POST', '/passkey/login/verify', ['ceremony' => 'x'])->status);
        self::assertSame(422, $this->call('POST', '/passkey/handoff/authorize', ['challenge' => self::CHALLENGE, 'port' => '51234', 'state' => self::STATE], $this->idToken())->status);
        self::assertSame(400, $this->call('POST', '/passkey/login/verify', ['ceremony' => 'unknown', 'credential' => []])->status);
        self::assertSame(404, $this->call('GET', '/passkey/nope')->status);
        self::assertNull($this->hub->handle(new HubRequest('GET', '/somewhere-else', [], '', '')));
    }

    public function test_well_known_documents_are_served(): void
    {
        $response = $this->call('GET', '/.well-known/webauthn');
        self::assertSame(200, $response->status);
        self::assertSame(['origins' => [self::WEB]], self::json($response));
    }
}
