<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase;

use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\NativeClock;

/**
 * Google's public certificates for Firebase ID tokens, cached for the `max-age` Google sends (never
 * longer than 24 hours). Across all processes that share the {@see KeyCache}, at most one fetch per
 * minute happens (also for unknown key IDs, after the cache expired, and while Google fails), so a
 * client sending made-up key IDs cannot make the server hammer Google. Within that minute the last
 * keys keep being used.
 */
final class GoogleKeySource implements KeySource
{
    public const URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';

    private const MAX_CACHE = 86400;

    private const DEFAULT_CACHE = 3600;

    private const REFETCH_INTERVAL = 60;

    private readonly ClockInterface $clock;

    public function __construct(
        private readonly HttpClient $http = new CurlHttpClient,
        private readonly KeyCache $cache = new MemoryKeyCache,
        private readonly string $url = self::URL,
        ?ClockInterface $clock = null,
    ) {
        $this->clock = $clock ?? new NativeClock;
    }

    public function key(string $kid): ?string
    {
        $now = $this->clock->now()->getTimestamp();
        $cached = $this->cache->get();
        if ($cached !== null) {
            $fresh = $cached['expiresAt'] > $now;
            if ($fresh && isset($cached['keys'][$kid])) {
                return $cached['keys'][$kid];
            }
            if ($now - $cached['fetchedAt'] < self::REFETCH_INTERVAL) {
                if ($cached['keys'] === []) {
                    throw FirebaseException::unavailable('Google public keys, recent fetch failed');
                }

                return $cached['keys'][$kid] ?? null;
            }
        }

        $keys = $this->fetch($now, $cached);

        return $keys[$kid] ?? null;
    }

    /**
     * @param  array{keys: array<string, string>, expiresAt: int, fetchedAt: int}|null  $previous
     * @return array<string, string>
     */
    private function fetch(int $now, ?array $previous): array
    {
        // Record the attempt first: a failing or slow Google must not be asked again by every request.
        $this->cache->put($previous['keys'] ?? [], $previous['expiresAt'] ?? 0, $now);
        $response = $this->http->request('GET', $this->url, ['Accept' => 'application/json']);
        if ($response->status !== 200) {
            throw FirebaseException::unavailable('Google public keys, HTTP '.$response->status);
        }
        $data = json_decode($response->body, true);
        if (! is_array($data) || $data === []) {
            throw FirebaseException::unavailable('Google public keys, unreadable answer');
        }
        $keys = [];
        foreach ($data as $kid => $pem) {
            if (is_string($kid) && is_string($pem) && str_contains($pem, '-----BEGIN')) {
                $keys[$kid] = $pem;
            }
        }
        if ($keys === []) {
            throw FirebaseException::unavailable('Google public keys, no keys in the answer');
        }
        $ttl = min(self::MAX_CACHE, max(0, $response->maxAge() ?? self::DEFAULT_CACHE));
        $this->cache->put($keys, $now + $ttl, $now);

        return $keys;
    }
}
