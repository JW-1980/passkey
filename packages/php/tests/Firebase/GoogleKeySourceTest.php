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

    public function test_the_refetch_limit_holds_across_instances_sharing_a_file_cache(): void
    {
        $path = sys_get_temp_dir().'/keys-'.bin2hex(random_bytes(4)).'.json';
        try {
            $http = $this->http();
            for ($i = 0; $i < 5; $i++) {
                // A new object per "request", as under PHP-FPM.
                self::assertNull((new GoogleKeySource($http, new FileKeyCache($path), clock: $this->clock))->key('made-up-'.$i));
            }
            self::assertCount(1, $http->requests);
        } finally {
            @unlink($path);
        }
    }

    public function test_a_failing_google_is_asked_at_most_once_a_minute_and_old_keys_stay_in_use(): void
    {
        $fail = false;
        $calls = 0;
        $http = new FakeHttp(function () use (&$fail, &$calls) {
            $calls++;

            return $fail ? new HttpResponse(503, [], '') : new HttpResponse(200, ['cache-control' => 'max-age=100'], (string) json_encode(['k1' => self::PEM]));
        });
        $cache = new MemoryKeyCache;
        $source = new GoogleKeySource($http, $cache, clock: $this->clock);
        self::assertSame(self::PEM, $source->key('k1'));

        $fail = true;
        $this->clock->sleep(101);
        try {
            $source->key('k1');
            self::fail('no exception');
        } catch (FirebaseException) {
            $this->addToAssertionCount(1);
        }
        // Within the minute after the failed attempt: no new request, the last keys are used.
        self::assertSame(self::PEM, (new GoogleKeySource($http, $cache, clock: $this->clock))->key('k1'));
        self::assertSame(2, $calls);
    }

    public function test_a_cache_file_writable_by_others_is_ignored(): void
    {
        $path = sys_get_temp_dir().'/keys-'.bin2hex(random_bytes(4)).'.json';
        try {
            file_put_contents($path, (string) json_encode(['keys' => ['k1' => 'forged'], 'expiresAt' => PHP_INT_MAX, 'fetchedAt' => time()]));
            chmod($path, 0666);
            self::assertNull((new FileKeyCache($path))->get());
            chmod($path, 0600);
            $entry = (new FileKeyCache($path))->get();
            self::assertNotNull($entry);
            self::assertLessThanOrEqual(time() + 86400, $entry['expiresAt'], 'expiry is capped at a day');
        } finally {
            @unlink($path);
        }
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
        $path = sys_get_temp_dir().'/keys-'.bin2hex(random_bytes(4)).'.json';
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
