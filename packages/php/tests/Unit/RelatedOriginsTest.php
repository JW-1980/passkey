<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Tests\Unit;

use InvalidArgumentException;
use Jw1980\Passkey\PasskeyException;
use Jw1980\Passkey\PasskeyServer;
use Jw1980\Passkey\RelyingParty;
use Jw1980\Passkey\Tests\Support\Fixture;
use Jw1980\Passkey\Tests\Support\SoftPasskey;
use Jw1980\Passkey\WellKnown;
use PHPUnit\Framework\TestCase;

final class RelatedOriginsTest extends TestCase
{
    private const OTHER = 'https://shop.other-brand.example';

    private function server(Fixture $fixture, RelyingParty $relyingParty): PasskeyServer
    {
        return new PasskeyServer($relyingParty, $fixture->credentials, $fixture->challenges, Fixture::SECRET, clock: $fixture->clock);
    }

    public function test_a_related_origin_on_another_domain_registers_and_signs_in(): void
    {
        $fixture = new Fixture;
        $server = $this->server($fixture, new RelyingParty('app.example', 'Example', [Fixture::ORIGIN], [self::OTHER]));
        $device = new SoftPasskey;

        $ceremony = $server->beginRegistration(Fixture::user());
        $server->finishRegistration($ceremony->id, $device->register($ceremony->publicKey, self::OTHER), Fixture::user());

        $login = $server->beginAuthentication();
        self::assertSame('user-1', $server->finishAuthentication($login->id, $device->assert($login->publicKey, self::OTHER))->userId);
    }

    public function test_an_unlisted_other_domain_is_refused(): void
    {
        $fixture = new Fixture;
        $device = $fixture->enroll();
        $login = $fixture->server->beginAuthentication();
        $this->expectException(PasskeyException::class);
        $fixture->server->finishAuthentication($login->id, $device->assert($login->publicKey, self::OTHER));
    }

    public function test_related_origins_must_be_https_origins(): void
    {
        foreach (['http://shop.other.example', 'https://shop.other.example/path', 'https://127.0.0.1', 'shop.other.example'] as $bad) {
            try {
                new RelyingParty('app.example', 'Example', [Fixture::ORIGIN], [$bad]);
                self::fail("accepted {$bad}");
            } catch (InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function test_well_known_document_lists_web_origins_only(): void
    {
        $relyingParty = new RelyingParty('app.example', 'Example', [Fixture::ORIGIN, WellKnown::androidOrigin(str_repeat('AB:', 31).'AB')], [self::OTHER, self::OTHER.':443']);
        self::assertSame(['origins' => [Fixture::ORIGIN, self::OTHER]], WellKnown::relatedOrigins($relyingParty));
    }
}
