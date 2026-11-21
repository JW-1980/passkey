<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Tests\Firebase;

use InvalidArgumentException;
use Jw1980\Passkey\Base64Url;
use Jw1980\Passkey\Firebase\CustomTokenIssuer;
use Jw1980\Passkey\Firebase\FirebaseException;
use Jw1980\Passkey\Firebase\Jwt;
use Jw1980\Passkey\Firebase\ServiceAccount;
use Jw1980\Passkey\Tests\Support\FirebaseKeys;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class CustomTokenIssuerTest extends TestCase
{
    public function test_token_has_the_format_firebase_requires_and_verifies_with_the_service_account_key(): void
    {
        $clock = new MockClock('2026-11-21 12:00:00', 'UTC');
        $issuer = new CustomTokenIssuer(FirebaseKeys::serviceAccount(), 300, $clock);

        $token = $issuer->issue('firebase-uid-1', ['login_method' => 'passkey', 'login_mfa' => true]);
        $jwt = Jwt::decode($token);

        self::assertSame(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => 'sa-key-1'], $jwt['header']);
        $now = $clock->now()->getTimestamp();
        self::assertSame([
            'iss' => FirebaseKeys::CLIENT_EMAIL,
            'sub' => FirebaseKeys::CLIENT_EMAIL,
            'aud' => 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit',
            'iat' => $now,
            'exp' => $now + 300,
            'uid' => 'firebase-uid-1',
            'claims' => ['login_method' => 'passkey', 'login_mfa' => true],
        ], $jwt['payload']);
        self::assertTrue(Jwt::verifyRs256($jwt['input'], $jwt['signature'], FirebaseKeys::pair('service-account')['public']));
        self::assertFalse(Jwt::verifyRs256($jwt['input'], $jwt['signature'], FirebaseKeys::pair('google')['public']));
    }

    public function test_without_claims_the_claims_field_is_absent(): void
    {
        $token = (new CustomTokenIssuer(FirebaseKeys::serviceAccount()))->issue('u');
        self::assertArrayNotHasKey('claims', Jwt::decode($token)['payload']);
    }

    public function test_reserved_claims_are_refused(): void
    {
        $issuer = new CustomTokenIssuer(FirebaseKeys::serviceAccount());
        foreach (['amr', 'firebase', 'sub', 'auth_time'] as $reserved) {
            try {
                $issuer->issue('u', [$reserved => 'x']);
                self::fail("'{$reserved}' was accepted");
            } catch (InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function test_uid_length_and_lifetime_are_bounded(): void
    {
        $issuer = new CustomTokenIssuer(FirebaseKeys::serviceAccount());
        $issuer->issue(str_repeat('a', 128));
        $this->expectException(InvalidArgumentException::class);
        $issuer->issue(str_repeat('a', 129));
    }

    public function test_empty_uid_is_refused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        (new CustomTokenIssuer(FirebaseKeys::serviceAccount()))->issue('');
    }

    public function test_lifetime_over_one_hour_is_refused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new CustomTokenIssuer(FirebaseKeys::serviceAccount(), 3601);
    }

    public function test_claims_over_1000_bytes_are_refused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        (new CustomTokenIssuer(FirebaseKeys::serviceAccount()))->issue('u', ['big' => str_repeat('x', 1000)]);
    }

    public function test_service_account_json_is_validated(): void
    {
        foreach ([
            '{',
            '{"type":"user"}',
            json_encode(['type' => 'service_account', 'project_id' => 'Bad_ID', 'client_email' => 'a@b.c', 'private_key' => 'x']),
            json_encode(['type' => 'service_account', 'project_id' => 'good-id', 'client_email' => 'nope', 'private_key' => 'x']),
            json_encode(['type' => 'service_account', 'project_id' => 'good-id', 'client_email' => 'a@b.c', 'private_key' => 'not a key']),
        ] as $json) {
            try {
                ServiceAccount::fromJson((string) $json);
                self::fail('accepted: '.$json);
            } catch (FirebaseException $refusal) {
                self::assertSame(FirebaseException::CONFIGURATION, $refusal->errorCode);
            }
        }
    }

    public function test_a_small_rsa_key_is_refused(): void
    {
        $key = openssl_pkey_new(['private_key_bits' => 1024, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        self::assertNotFalse($key);
        openssl_pkey_export($key, $pem);
        $this->expectException(FirebaseException::class);
        ServiceAccount::fromParts('good-project', 'a@b.c', (string) $pem);
    }

    public function test_the_key_never_appears_in_a_dump(): void
    {
        $dump = print_r(FirebaseKeys::serviceAccount(), true).var_export(FirebaseKeys::serviceAccount()->__debugInfo(), true);
        self::assertStringNotContainsString('PRIVATE KEY', $dump);
        self::assertStringContainsString(FirebaseKeys::CLIENT_EMAIL, $dump);
    }

    public function test_signature_segment_is_base64url(): void
    {
        $parts = explode('.', (new CustomTokenIssuer(FirebaseKeys::serviceAccount()))->issue('u'));
        self::assertNotNull(Base64Url::decode($parts[2]));
    }
}
