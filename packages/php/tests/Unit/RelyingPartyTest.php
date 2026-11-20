<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Tests\Unit;

use InvalidArgumentException;
use Jw1980\Passkey\Base64Url;
use Jw1980\Passkey\RelyingParty;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class RelyingPartyTest extends TestCase
{
    public function test_origins_are_normalized_and_deduplicated(): void
    {
        $android = 'android:apk-key-hash:'.Base64Url::encode(str_repeat("\x01", 32));
        $party = new RelyingParty('example.com', 'Example', [
            'https://Example.com/', 'https://example.com:443', ' https://app.example.com:8443 ', $android,
        ]);

        self::assertSame(['https://example.com', 'https://app.example.com:8443', $android], $party->origins);
    }

    public function test_localhost_may_use_http_for_development(): void
    {
        $party = RelyingParty::forUrl('http://localhost:8000', 'Dev');

        self::assertSame('localhost', $party->id);
        self::assertSame(['http://localhost:8000'], $party->origins);
    }

    public function test_for_url_takes_the_host_as_the_id(): void
    {
        $party = RelyingParty::forUrl('https://App.Example.com/', 'Example');

        self::assertSame('app.example.com', $party->id);
        self::assertSame(['https://app.example.com'], $party->origins);
    }

    /** @return array<string, array{string, list<string>}> */
    public static function refused(): array
    {
        $hash = Base64Url::encode(str_repeat("\x01", 32));

        return [
            'an IP address as ID' => ['127.0.0.1', ['https://127.0.0.1']],
            'a URL as ID' => ['https://example.com', ['https://example.com']],
            'an uppercase ID' => ['Example.com', ['https://example.com']],
            'a single label that is not localhost' => ['intranet', ['https://intranet']],
            'no origins' => ['example.com', []],
            'http outside localhost' => ['example.com', ['http://example.com']],
            'http localhost for a real domain' => ['example.com', ['http://localhost:8000']],
            'an origin of another site' => ['example.com', ['https://example.org']],
            'a look-alike suffix' => ['example.com', ['https://evilexample.com']],
            'a parent domain' => ['app.example.com', ['https://example.com']],
            'an origin with a path' => ['example.com', ['https://example.com/login']],
            'an origin with a query' => ['example.com', ['https://example.com?x=1']],
            'an origin with credentials' => ['example.com', ['https://user@example.com']],
            'an android origin with a short hash' => ['example.com', ['android:apk-key-hash:'.Base64Url::encode('short')]],
            'an android origin with a padded hash' => ['example.com', ["android:apk-key-hash:{$hash}="]],
            'a custom scheme' => ['example.com', ['tauri://localhost']],
        ];
    }

    /** @param list<string> $origins */
    #[DataProvider('refused')]
    public function test_an_unsafe_configuration_is_refused(string $id, array $origins): void
    {
        $this->expectException(InvalidArgumentException::class);
        new RelyingParty($id, 'Example', $origins);
    }

    public function test_a_name_is_required(): void
    {
        $this->expectException(InvalidArgumentException::class);
        new RelyingParty('example.com', '  ', ['https://example.com']);
    }
}
