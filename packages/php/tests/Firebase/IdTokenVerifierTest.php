<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Tests\Firebase;

use InvalidArgumentException;
use Jw1980\Passkey\Firebase\FirebaseException;
use Jw1980\Passkey\Firebase\IdTokenVerifier;
use Jw1980\Passkey\Tests\Support\FirebaseKeys;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class IdTokenVerifierTest extends TestCase
{
    private MockClock $clock;

    private IdTokenVerifier $verifier;

    private int $now;

    protected function setUp(): void
    {
        $this->clock = new MockClock('2026-11-21 12:00:00', 'UTC');
        $this->now = $this->clock->now()->getTimestamp();
        $this->verifier = IdTokenVerifier::forProject(FirebaseKeys::PROJECT, new FirebaseKeys, $this->clock);
    }

    public function test_a_valid_token_gives_the_identity(): void
    {
        $identity = $this->verifier->verify(FirebaseKeys::idToken($this->now, ['name' => 'Ann', 'picture' => 'https://img.example/a.png']));

        self::assertSame('firebase-uid-1', $identity->uid);
        self::assertSame('ann@example.com', $identity->email);
        self::assertTrue($identity->emailVerified);
        self::assertSame('Ann', $identity->name);
        self::assertSame('https://img.example/a.png', $identity->picture);
        self::assertSame('password', $identity->signInProvider);
        self::assertSame('password', $identity->method());
        self::assertNull($identity->loginMethod());
        self::assertFalse($identity->isMultiFactor());
        self::assertSame($this->now - 30, $identity->authTime);
        self::assertSame($this->now + 3570, $identity->expiresAt);
        self::assertTrue($identity->isRecent(60));
        self::assertFalse($identity->isRecent(29));
    }

    /** @return iterable<string, array{array<string, mixed>, array<string, mixed>, string}> */
    public static function broken(): iterable
    {
        $rs = ['alg' => 'RS256', 'kid' => FirebaseKeys::KID, 'typ' => 'JWT'];
        yield 'alg none' => [[], ['alg' => 'none', 'typ' => 'JWT'], 'google'];
        yield 'alg HS256' => [[], ['alg' => 'HS256', 'kid' => FirebaseKeys::KID], 'google'];
        yield 'no kid' => [[], ['alg' => 'RS256'], 'google'];
        yield 'unknown kid' => [[], ['alg' => 'RS256', 'kid' => 'other'], 'google'];
        yield 'signed by another key' => [[], $rs, 'service-account'];
        yield 'other issuer' => [['iss' => 'https://securetoken.google.com/other-project'], $rs, 'google'];
        yield 'other audience' => [['aud' => 'other-project'], $rs, 'google'];
        yield 'expired' => [['exp' => -61], $rs, 'google'];
        yield 'issued in the future' => [['iat' => 120], $rs, 'google'];
        yield 'signed in in the future' => [['auth_time' => 120], $rs, 'google'];
        yield 'empty subject' => [['sub' => '', 'user_id' => ''], $rs, 'google'];
        yield 'subject over 128' => [['sub' => str_repeat('a', 129), 'user_id' => str_repeat('a', 129)], $rs, 'google'];
        yield 'user_id differs' => [['user_id' => 'someone-else'], $rs, 'google'];
        yield 'exp as text' => [['exp' => 'soon'], $rs, 'google'];
        yield 'no provider' => [['firebase' => []], $rs, 'google'];
    }

    /**
     * @param  array<string, mixed>  $claims  Relative times are added to now.
     * @param  array<string, mixed>  $header
     */
    #[DataProvider('broken')]
    public function test_broken_tokens_are_refused(array $claims, array $header, string $signWith): void
    {
        foreach (['exp', 'iat', 'auth_time'] as $time) {
            if (isset($claims[$time]) && is_int($claims[$time])) {
                $claims[$time] += $this->now;
            }
        }
        try {
            $this->verifier->verify(FirebaseKeys::idToken($this->now, $claims, $header, $signWith));
            self::fail('A broken token was accepted.');
        } catch (FirebaseException $refusal) {
            self::assertSame(FirebaseException::INVALID_TOKEN, $refusal->errorCode);
            self::assertSame(401, $refusal->httpStatus);
            self::assertSame('Please sign in again.', $refusal->getMessage());
        }
    }

    public function test_tampered_payload_is_refused(): void
    {
        [$h, , $s] = explode('.', FirebaseKeys::idToken($this->now));
        $other = explode('.', FirebaseKeys::idToken($this->now, ['sub' => 'mallory', 'user_id' => 'mallory']))[1];
        $this->expectException(FirebaseException::class);
        $this->verifier->verify("{$h}.{$other}.{$s}");
    }

    public function test_garbage_is_refused(): void
    {
        foreach (['', 'a.b', 'a.b.c.d', '!!!.???.***', str_repeat('a', 20000)] as $garbage) {
            try {
                $this->verifier->verify($garbage);
                self::fail('garbage accepted');
            } catch (FirebaseException $refusal) {
                self::assertSame(FirebaseException::INVALID_TOKEN, $refusal->errorCode);
            }
        }
    }

    public function test_clock_skew_of_one_minute_is_allowed(): void
    {
        $identity = $this->verifier->verify(FirebaseKeys::idToken($this->now, ['iat' => $this->now + 50, 'auth_time' => $this->now + 50, 'exp' => $this->now - 50]));
        self::assertSame('firebase-uid-1', $identity->uid);
    }

    public function test_passkey_sign_in_is_multi_factor(): void
    {
        $identity = $this->verifier->verify(FirebaseKeys::idToken($this->now, [
            'login_method' => 'passkey', 'login_mfa' => true,
            'firebase' => ['identities' => [], 'sign_in_provider' => 'custom'],
        ]));
        self::assertSame('passkey', $identity->loginMethod());
        self::assertSame('passkey', $identity->method());
        self::assertTrue($identity->isMultiFactor());
    }

    public function test_login_claims_are_ignored_unless_the_provider_is_custom(): void
    {
        // A claim set through setCustomUserClaims on a password user must not pass as a passkey.
        $identity = $this->verifier->verify(FirebaseKeys::idToken($this->now, ['login_method' => 'passkey', 'login_mfa' => true]));
        self::assertNull($identity->loginMethod());
        self::assertSame('password', $identity->method());
        self::assertFalse($identity->isMultiFactor());
    }

    public function test_handoff_reports_the_browser_method(): void
    {
        $identity = $this->verifier->verify(FirebaseKeys::idToken($this->now, [
            'login_method' => 'handoff', 'login_via' => 'google.com', 'login_mfa' => false,
            'firebase' => ['sign_in_provider' => 'custom'],
        ]));
        self::assertSame('google.com', $identity->method());
        self::assertFalse($identity->isMultiFactor());
    }

    public function test_firebase_mfa_is_multi_factor(): void
    {
        $identity = $this->verifier->verify(FirebaseKeys::idToken($this->now, [
            'firebase' => ['sign_in_provider' => 'password', 'sign_in_second_factor' => 'totp'],
        ]));
        self::assertSame('totp', $identity->secondFactor);
        self::assertTrue($identity->isMultiFactor());
    }

    public function test_emulator_mode_only_for_demo_projects(): void
    {
        $this->expectException(InvalidArgumentException::class);
        IdTokenVerifier::forEmulator('real-project-1');
    }

    public function test_emulator_mode_accepts_unsigned_tokens_of_its_project_only(): void
    {
        $verifier = IdTokenVerifier::forEmulator('demo-shop', $this->clock);
        $token = FirebaseKeys::idToken($this->now, ['iss' => 'https://securetoken.google.com/demo-shop', 'aud' => 'demo-shop'], ['alg' => 'none', 'typ' => 'JWT']);
        self::assertSame('firebase-uid-1', $verifier->verify($token)->uid);

        $this->expectException(FirebaseException::class);
        $verifier->verify(FirebaseKeys::idToken($this->now, [], ['alg' => 'none', 'typ' => 'JWT']));
    }

    public function test_emulator_mode_refuses_signed_tokens(): void
    {
        $verifier = IdTokenVerifier::forEmulator('demo-shop', $this->clock);
        $this->expectException(FirebaseException::class);
        $verifier->verify(FirebaseKeys::idToken($this->now, ['iss' => 'https://securetoken.google.com/demo-shop', 'aud' => 'demo-shop']));
    }

    public function test_invalid_project_id_is_refused(): void
    {
        $this->expectException(InvalidArgumentException::class);
        IdTokenVerifier::forProject('No Such Project');
    }
}
