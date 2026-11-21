<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Tests\Firebase;

use Jw1980\Passkey\Firebase\AdminClient;
use Jw1980\Passkey\Firebase\CurlHttpClient;
use Jw1980\Passkey\Firebase\CustomTokenIssuer;
use Jw1980\Passkey\Firebase\IdTokenVerifier;
use Jw1980\Passkey\Tests\Support\FirebaseKeys;
use PHPUnit\Framework\TestCase;

/**
 * Against a running Firebase Auth emulator: our custom token is accepted by Firebase and ends in an
 * ID token for the same uid, with our claims; the admin client works. Skipped without
 * `FIREBASE_AUTH_EMULATOR_HOST` (for example `127.0.0.1:9099`). The project is `FIREBASE_PROJECT_ID`
 * (default `demo-passkey-test`), which must be the emulator's project.
 */
final class EmulatorTest extends TestCase
{
    private string $host;

    protected function setUp(): void
    {
        $host = getenv('FIREBASE_AUTH_EMULATOR_HOST');
        if (! is_string($host) || $host === '') {
            self::markTestSkipped('FIREBASE_AUTH_EMULATOR_HOST is not set; start the Firebase Auth emulator to run this test.');
        }
        $this->host = $host;
        $project = getenv('FIREBASE_PROJECT_ID');
        $this->project = is_string($project) && $project !== '' ? $project : 'demo-passkey-test';
    }

    private string $project;

    /** @return array<string, mixed> */
    private function post(string $path, array $body): array
    {
        $response = (new CurlHttpClient)->request('POST', 'http://'.$this->host.'/'.$path, ['Content-Type' => 'application/json'], (string) json_encode($body));
        $data = json_decode($response->body, true);
        self::assertSame(200, $response->status, $response->body);
        self::assertIsArray($data);

        return $data;
    }

    public function test_custom_token_signs_in_the_same_uid_with_our_claims(): void
    {
        $uid = 'emulator-'.bin2hex(random_bytes(6));
        $token = (new CustomTokenIssuer(FirebaseKeys::serviceAccount($this->project)))->issue($uid, ['login_method' => 'passkey', 'login_mfa' => true]);

        $answer = $this->post('identitytoolkit.googleapis.com/v1/accounts:signInWithCustomToken?key=fake-api-key', ['token' => $token, 'returnSecureToken' => true]);
        self::assertIsString($answer['idToken']);

        $identity = IdTokenVerifier::forEmulator($this->project)->verify($answer['idToken']);
        self::assertSame($uid, $identity->uid);
        self::assertSame('custom', $identity->signInProvider);
        self::assertSame('passkey', $identity->loginMethod());
        self::assertTrue($identity->isMultiFactor());

        // The claims survive a refresh of the ID token.
        $refreshed = $this->post('securetoken.googleapis.com/v1/token?key=fake-api-key', ['grant_type' => 'refresh_token', 'refresh_token' => $answer['refreshToken']]);
        $again = IdTokenVerifier::forEmulator($this->project)->verify((string) $refreshed['id_token']);
        self::assertSame($uid, $again->uid);
        self::assertSame('passkey', $again->loginMethod());
    }

    public function test_admin_client_looks_up_disables_revokes_and_deletes(): void
    {
        $created = $this->post('identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake-api-key', [
            'email' => 'admin-'.bin2hex(random_bytes(4)).'@example.com', 'password' => 'a long password 123', 'returnSecureToken' => true,
        ]);
        $uid = (string) $created['localId'];
        $admin = AdminClient::forEmulator($this->project, $this->host);

        $user = $admin->lookup($uid);
        self::assertNotNull($user);
        self::assertFalse($user['disabled']);

        $identity = IdTokenVerifier::forEmulator($this->project)->verify((string) $created['idToken']);
        self::assertTrue($admin->isActive($identity));

        $admin->setDisabled($uid, true);
        self::assertTrue($admin->lookup($uid)['disabled'] ?? false);
        self::assertFalse($admin->isActive($identity));
        $admin->setDisabled($uid, false);

        sleep(1);
        $admin->revokeRefreshTokens($uid);
        self::assertFalse($admin->isActive($identity), 'tokens from before the revocation are refused');

        $admin->delete($uid);
        self::assertNull($admin->lookup($uid));
    }
}
