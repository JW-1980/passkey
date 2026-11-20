<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Tests\Unit;

use InvalidArgumentException;
use Jw1980\Passkey\Base64Url;
use Jw1980\Passkey\PasskeyException;
use Jw1980\Passkey\PasskeyUser;
use Jw1980\Passkey\WellKnown;
use PHPUnit\Framework\TestCase;

final class SmallPartsTest extends TestCase
{
    private const FINGERPRINT = 'FA:C6:17:45:DC:09:03:78:6F:B9:ED:E6:2A:96:2B:39:9F:73:48:F0:BB:6F:89:9B:83:32:66:75:91:03:3B:9C';

    public function test_base64url_round_trips_and_rejects_other_encodings(): void
    {
        // RFC 4648 §10 test vectors, without padding.
        foreach (['f' => 'Zg', 'fo' => 'Zm8', 'foo' => 'Zm9v', 'foob' => 'Zm9vYg', "\xfb\xff" => '-_8'] as $bytes => $text) {
            self::assertSame($text, Base64Url::encode((string) $bytes));
            self::assertSame((string) $bytes, Base64Url::decode($text));
        }
        foreach (['', 'Zg==', '+/8', 'Zm 9v', 'Z', 'Zh'] as $bad) {
            self::assertNull(Base64Url::decode($bad), "'{$bad}' must be refused");
        }
    }

    public function test_the_android_origin_is_the_base64url_hash_of_the_certificate(): void
    {
        // The example of Android's Credential Manager documentation.
        $origin = WellKnown::androidOrigin(self::FINGERPRINT);

        self::assertSame('android:apk-key-hash:-sYXRdwJA3hvue3mKpYrOZ9zSPC7b4mbgzJmdZEDO5w', $origin);
        self::assertSame($origin, WellKnown::androidOrigin(strtolower(str_replace(':', '', self::FINGERPRINT))));
    }

    public function test_asset_links_grant_login_credentials_to_the_app(): void
    {
        $links = WellKnown::assetLinks('nl.example.app', [strtolower(str_replace(':', '', self::FINGERPRINT))]);

        self::assertSame([[
            'relation' => ['delegate_permission/common.handle_all_urls', 'delegate_permission/common.get_login_creds'],
            'target' => ['namespace' => 'android_app', 'package_name' => 'nl.example.app', 'sha256_cert_fingerprints' => [self::FINGERPRINT]],
        ]], $links);
    }

    public function test_apple_association_lists_the_apps(): void
    {
        self::assertSame(
            ['webcredentials' => ['apps' => ['A1B2C3D4E5.nl.example.app']]],
            WellKnown::appleAppSiteAssociation(['A1B2C3D4E5.nl.example.app']),
        );
    }

    public function test_well_known_input_is_validated(): void
    {
        $bad = [
            fn () => WellKnown::androidOrigin('AB:CD'),
            fn () => WellKnown::androidOrigin(str_repeat('zz', 32)),
            fn () => WellKnown::assetLinks('notapackage', [self::FINGERPRINT]),
            fn () => WellKnown::assetLinks('nl.example.app', []),
            fn () => WellKnown::appleAppSiteAssociation([]),
            fn () => WellKnown::appleAppSiteAssociation(['nl.example.app']),
            fn () => new PasskeyUser('', 'a', 'b'),
            fn () => new PasskeyUser(str_repeat('x', 192), 'a', 'b'),
            fn () => new PasskeyUser('1', ' ', 'b'),
        ];
        foreach ($bad as $index => $attempt) {
            try {
                $attempt();
                self::fail("Case {$index} must be refused.");
            } catch (InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function test_a_refusal_renders_without_its_cause(): void
    {
        $refusal = PasskeyException::invalidPasskey(new InvalidArgumentException('internal detail'));

        self::assertSame(['error' => ['code' => 'invalid_passkey', 'message' => 'This passkey is not valid.']], $refusal->toArray());
        self::assertSame('internal detail', $refusal->getPrevious()?->getMessage());
    }
}
