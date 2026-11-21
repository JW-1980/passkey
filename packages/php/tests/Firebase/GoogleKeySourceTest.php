<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Tests\Firebase;

use Jw1980\Passkey\Firebase\FileKeyCache;
use Jw1980\Passkey\Firebase\FirebaseException;
use Jw1980\Passkey\Firebase\GoogleKeySource;
use Jw1980\Passkey\Firebase\HttpResponse;
use Jw1980\Passkey\Firebase\MemoryKeyCache;
use Jw1980\Passkey\Tests\Support\FakeHttp;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

final class GoogleKeySourceTest extends TestCase
{
    private const PEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";

    private MockClock $clock;

    protected function setUp(): void
    {
        $this->clock = new MockClock('2026-11-21 12:00:00', 'UTC');
    }

    private function http(string $cacheControl = 'public, max-age=19302, must-revalidate, no-transform', int $status = 200): FakeHttp
    {
        return new FakeHttp(static fn () => new HttpResponse($status, ['cache-control' => $cacheControl], (string) json_encode(['k1' => self::PEM, 'k2' => self::PEM])));
    }

    public function test_keys_are_fetched_once_and_cached_for_max_age(): void
    {
        $http = $this->http();
        $source = new GoogleKeySource($http, new MemoryKeyCache, clock: $this->clock);

        self::assertSame(self::PEM, $source->key('k1'));
        self::assertSame(self::PEM, $source->key('k2'));
        self::assertCount(1, $http->requests);
        self::assertSame(GoogleKeySource::URL, $http->requests[0]['url']);

        $this->clock->sleep(19301);
        $source->key('k1');
        self::assertCount(1, $http->requests);
        $this->clock->sleep(2);
        $source->key('k1');
        self::assertCount(2, $http->requests);
    }

    public function test_cache_never_lasts_longer_than_a_day(): void
    {
        $http = $this->http('max-age=999999');
        $source = new GoogleKeySource($http, new MemoryKeyCache, clock: $this->clock);
        $source->key('k1');
        $this->clock->sleep(86401);
        $source->key('k1');
        self::assertCount(2, $http->requests);
    }

    public function test_unknown_kid_refetches_at_most_once_a_minute(): void
    {
        $http = $this->http();
        $source = new GoogleKeySource($http, new MemoryKeyCache, clock: $this->clock);
        self::assertNull($source->key('nope'));
        self::assertNull($source->key('nope'));
        self::assertNull($source->key('nope'));
        self::assertCount(1, $http->requests);
        $this->clock->sleep(61);
        self::assertNull($source->key('nope'));
        self::assertCount(2, $http->requests);
    }

    public function test_failure_is_unavailable_not_a_refusal(): void
    {
        $source = new GoogleKeySource($this->http(status: 500), new MemoryKeyCache, clock: $this->clock);
        try {
            $source->key('k1');
            self::fail('no exception');
        } catch (FirebaseException $failure) {
            self::assertSame(FirebaseException::UNAVAILABLE, $failure->errorCode);
            self::assertSame(503, $failure->httpStatus);
        }
    }

    public function test_answer_without_keys_is_unavailable(): void
    {
        $source = new GoogleKeySource(new FakeHttp(static fn () => new HttpResponse(200, [], '{"k1":"not a pem"}')), new MemoryKeyCache, clock: $this->clock);
        $this->expectException(FirebaseException::class);
        $source->key('k1');
    }

    public function test_file_cache_is_shared_between_instances(): void
    {
        $path = tempnam(sys_get_temp_dir(), 'keys');
        self::assertIsString($path);
        unlink($path);
        try {
            $http = $this->http();
            (new GoogleKeySource($http, new FileKeyCache($path), clock: $this->clock))->key('k1');
            (new GoogleKeySource($http, new FileKeyCache($path), clock: $this->clock))->key('k2');
            self::assertCount(1, $http->requests);
            self::assertStringNotContainsString('PRIVATE', (string) file_get_contents($path));
        } finally {
            @unlink($path);
        }
    }
}
