<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Tests\Firebase;

use InvalidArgumentException;
use Jw1980\Passkey\Firebase\AdminClient;
use Jw1980\Passkey\Firebase\FirebaseException;
use Jw1980\Passkey\Firebase\HttpResponse;
use Jw1980\Passkey\Firebase\IdTokenVerifier;
use Jw1980\Passkey\Firebase\Jwt;
use Jw1980\Passkey\Tests\Support\FakeHttp;
use Jw1980\Passkey\Tests\Support\FirebaseKeys;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class AdminClientTest extends TestCase
{
    /** @var list<array{int, string}> */
    private array $answers = [];

    private function http(): FakeHttp
    {
        return new FakeHttp(function (string $method, string $url) {
            if ($url === 'https://oauth2.googleapis.com/token') {
                return new HttpResponse(200, [], '{"access_token":"ya29.test","expires_in":3599,"token_type":"Bearer"}');
            }
            [$status, $body] = array_shift($this->answers) ?? [200, '{}'];

            return new HttpResponse($status, [], $body);
        });
    }

    public function test_service_account_obtains_an_access_token_with_a_signed_assertion_and_reuses_it(): void
    {
        $clock = new MockClock('2026-11-21 12:00:00', 'UTC');
        $http = $this->http();
        $admin = AdminClient::forServiceAccount(FirebaseKeys::serviceAccount(), $http, $clock);
        $this->answers = [[200, '{}'], [200, '{}']];

        $admin->revokeRefreshTokens('uid-1');
        $admin->setDisabled('uid-1', true);

        self::assertCount(3, $http->requests);
        parse_str((string) $http->requests[0]['body'], $form);
        self::assertSame('urn:ietf:params:oauth:grant-type:jwt-bearer', $form['grant_type']);
        $assertion = Jwt::decode((string) $form['assertion']);
        self::assertSame(FirebaseKeys::CLIENT_EMAIL, $assertion['payload']['iss']);
        self::assertSame('https://oauth2.googleapis.com/token', $assertion['payload']['aud']);
        self::assertTrue(Jwt::verifyRs256($assertion['input'], $assertion['signature'], FirebaseKeys::pair('service-account')['public']));

        self::assertSame('https://identitytoolkit.googleapis.com/v1/projects/'.FirebaseKeys::PROJECT.'/accounts:update', $http->requests[1]['url']);
        self::assertSame('Bearer ya29.test', $http->requests[1]['headers']['Authorization']);
        self::assertSame(['localId' => 'uid-1', 'validSince' => (string) $clock->now()->getTimestamp()], json_decode((string) $http->requests[1]['body'], true));
        self::assertSame(['localId' => 'uid-1', 'disableUser' => true], json_decode((string) $http->requests[2]['body'], true));
    }

    public function test_lookup_and_revocation_check(): void
    {
        $clock = new MockClock('2026-11-21 12:00:00', 'UTC');
        $now = $clock->now()->getTimestamp();
        $admin = AdminClient::forServiceAccount(FirebaseKeys::serviceAccount(), $this->http(), $clock);
        $verifier = IdTokenVerifier::forProject(FirebaseKeys::PROJECT, new FirebaseKeys, $clock);
        $identity = $verifier->verify(FirebaseKeys::idToken($now));

        $this->answers = [[200, json_encode(['users' => [['localId' => 'firebase-uid-1', 'email' => 'ann@example.com', 'validSince' => (string) ($now - 3600)]]])]];
        self::assertTrue($admin->isActive($identity));

        $this->answers = [[200, json_encode(['users' => [['localId' => 'firebase-uid-1', 'validSince' => (string) ($now - 10)]]])]];
        self::assertFalse($admin->isActive($identity), 'signed in before the revocation');

        $this->answers = [[200, json_encode(['users' => [['localId' => 'firebase-uid-1', 'disabled' => true]]])]];
        self::assertFalse($admin->isActive($identity), 'disabled');

        $this->answers = [[200, '{"kind":"identitytoolkit#GetAccountInfoResponse"}']];
        self::assertNull($admin->lookup('firebase-uid-1'));
    }

    public function test_refusals_and_outages_are_told_apart(): void
    {
        $admin = AdminClient::forServiceAccount(FirebaseKeys::serviceAccount(), $this->http());
        $this->answers = [[400, '{"error":{"code":400,"message":"USER_NOT_FOUND"}}'], [503, '']];
        try {
            $admin->delete('x');
            self::fail('no exception');
        } catch (FirebaseException $refusal) {
            self::assertSame(FirebaseException::ADMIN_REFUSED, $refusal->errorCode);
            self::assertStringContainsString('USER_NOT_FOUND', $refusal->getMessage());
        }
        try {
            $admin->delete('x');
            self::fail('no exception');
        } catch (FirebaseException $failure) {
            self::assertSame(FirebaseException::UNAVAILABLE, $failure->errorCode);
        }
    }

    public function test_emulator_uses_the_owner_bearer_and_only_for_demo_projects(): void
    {
        $http = $this->http();
        AdminClient::forEmulator('demo-shop', '127.0.0.1:9099', $http)->delete('u');
        self::assertSame('http://127.0.0.1:9099/identitytoolkit.googleapis.com/v1/projects/demo-shop/accounts:delete', $http->requests[0]['url']);
        self::assertSame('Bearer owner', $http->requests[0]['headers']['Authorization']);

        $this->expectException(InvalidArgumentException::class);
        AdminClient::forEmulator('real-shop', '127.0.0.1:9099');
    }
}
