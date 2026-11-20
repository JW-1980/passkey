<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Tests\Unit;

use InvalidArgumentException;
use Jw1980\Passkey\Base64Url;
use Jw1980\Passkey\Handoff\HandoffServer;
use Jw1980\Passkey\PasskeyException;
use Jw1980\Passkey\Tests\Support\Fixture;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class HandoffServerTest extends TestCase
{
    /** RFC 7636 Appendix B. */
    private const VERIFIER = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

    private const CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

    private const STATE = 'c3RhdGUtb2YtNDMtY2hhcmFjdGVycy1iYXNlNjR1cmw';

    private Fixture $fixture;

    private HandoffServer $handoff;

    protected function setUp(): void
    {
        $this->fixture = new Fixture;
        $this->handoff = new HandoffServer($this->fixture->challenges);
    }

    private function code(string $redirect): string
    {
        parse_str((string) parse_url($redirect, PHP_URL_QUERY), $query);

        return (string) $query['code'];
    }

    private function refusedExchange(string $code, string $verifier): void
    {
        try {
            $this->handoff->exchange($code, $verifier);
            self::fail('Expected a refusal.');
        } catch (PasskeyException $refusal) {
            self::assertSame(PasskeyException::INVALID_HANDOFF, $refusal->errorCode);
            self::assertSame(400, $refusal->httpStatus);
        }
    }

    public function test_the_code_goes_to_the_loopback_address_and_redeems_with_the_verifier(): void
    {
        $redirect = $this->handoff->authorize('user-1', self::CHALLENGE, 51234, self::STATE, ['secondFactor' => true]);

        self::assertMatchesRegularExpression(
            '#^http://127\.0\.0\.1:51234/callback\?code=[A-Za-z0-9_-]{43}&state='.self::STATE.'$#',
            $redirect,
        );
        $grant = $this->handoff->exchange($this->code($redirect), self::VERIFIER);
        self::assertSame('user-1', $grant->userId);
        self::assertSame(['secondFactor' => true], $grant->context);
    }

    public function test_every_code_is_different(): void
    {
        $a = $this->code($this->handoff->authorize('user-1', self::CHALLENGE, 51234, self::STATE));
        $b = $this->code($this->handoff->authorize('user-1', self::CHALLENGE, 51234, self::STATE));

        self::assertNotSame($a, $b);
    }

    public function test_a_code_redeems_only_once(): void
    {
        $code = $this->code($this->handoff->authorize('user-1', self::CHALLENGE, 51234, self::STATE));
        $this->handoff->exchange($code, self::VERIFIER);

        $this->refusedExchange($code, self::VERIFIER);
    }

    public function test_a_wrong_verifier_is_refused_and_spends_the_code(): void
    {
        $code = $this->code($this->handoff->authorize('user-1', self::CHALLENGE, 51234, self::STATE));

        $this->refusedExchange($code, str_repeat('a', 43));
        $this->refusedExchange($code, self::VERIFIER);
    }

    public function test_a_code_expires(): void
    {
        $code = $this->code($this->handoff->authorize('user-1', self::CHALLENGE, 51234, self::STATE));
        $this->fixture->clock->sleep(60);

        $this->refusedExchange($code, self::VERIFIER);
    }

    public function test_an_unknown_or_malformed_code_or_verifier_is_refused(): void
    {
        $code = $this->code($this->handoff->authorize('user-1', self::CHALLENGE, 51234, self::STATE));

        $this->refusedExchange(Base64Url::encode(random_bytes(32)), self::VERIFIER);
        $this->refusedExchange('', self::VERIFIER);
        $this->refusedExchange($code.'x', self::VERIFIER);
        $this->refusedExchange($code, 'too-short');
        $this->refusedExchange($code, str_repeat('a', 129));
        $this->refusedExchange($code, self::VERIFIER.'%');
        // None of those reached the store, so the real pair still works.
        self::assertSame('user-1', $this->handoff->exchange($code, self::VERIFIER)->userId);
    }

    public function test_a_passkey_ceremony_id_is_not_a_handoff_code(): void
    {
        $ceremony = $this->fixture->server->beginAuthentication();

        $this->refusedExchange($ceremony->id, self::VERIFIER);
    }

    /** @return array<string, array{string, string, int, string}> */
    public static function badRequests(): array
    {
        return [
            'no account' => ['', self::CHALLENGE, 51234, self::STATE],
            'a short challenge' => ['user-1', 'short', 51234, self::STATE],
            'a challenge with other characters' => ['user-1', str_repeat('+', 43), 51234, self::STATE],
            'a state that breaks out of the query' => ['user-1', self::CHALLENGE, 51234, substr(self::STATE, 0, 38).'&x=1#'],
            'a privileged port' => ['user-1', self::CHALLENGE, 1023, self::STATE],
            'a port out of range' => ['user-1', self::CHALLENGE, 65536, self::STATE],
            'a negative port' => ['user-1', self::CHALLENGE, -1, self::STATE],
        ];
    }

    #[DataProvider('badRequests')]
    public function test_an_invalid_request_gets_no_code(string $userId, string $challenge, int $port, string $state): void
    {
        try {
            $this->handoff->authorize($userId, $challenge, $port, $state);
            self::fail('Expected a refusal.');
        } catch (PasskeyException $refusal) {
            self::assertSame(PasskeyException::INVALID_REQUEST, $refusal->errorCode);
        }
        self::assertSame(0, (int) $this->fixture->pdo->query('SELECT COUNT(*) FROM passkey_challenges')->fetchColumn());
    }

    public function test_the_callback_path_is_configurable_but_cannot_carry_a_host_or_query(): void
    {
        $custom = new HandoffServer($this->fixture->challenges, '/terug');
        self::assertStringStartsWith('http://127.0.0.1:1024/terug?code=', $custom->authorize('user-1', self::CHALLENGE, 1024, self::STATE));

        foreach (['callback', '/cb?x=1', '/cb#f', '@evil.example/', '/a b'] as $path) {
            try {
                new HandoffServer($this->fixture->challenges, $path);
                self::fail("'{$path}' must be refused.");
            } catch (InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }
}
