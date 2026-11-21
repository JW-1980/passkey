<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase;

use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\NativeClock;

/**
 * Google's public certificates for Firebase ID tokens, cached for the `max-age` Google sends (never
 * longer than 24 hours). An unknown key ID causes at most one extra fetch per minute, so a client
 * sending made-up key IDs cannot make the server hammer Google.
 */
final class GoogleKeySource implements KeySource
{
    public const URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';

    private const MAX_CACHE = 86400;

    private const DEFAULT_CACHE = 3600;

    private const REFETCH_INTERVAL = 60;

    private readonly ClockInterface $clock;

    private int $lastFetch = 0;

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
        if ($cached !== null && $cached['expiresAt'] > $now) {
            if (isset($cached['keys'][$kid])) {
                return $cached['keys'][$kid];
            }
            if ($now - $this->lastFetch < self::REFETCH_INTERVAL) {
                return null;
            }
        }

        $keys = $this->fetch($now);

        return $keys[$kid] ?? null;
    }

    /** @return array<string, string> */
    private function fetch(int $now): array
    {
        $this->lastFetch = $now;
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
        $this->cache->put($keys, $now + $ttl);

        return $keys;
    }
}
