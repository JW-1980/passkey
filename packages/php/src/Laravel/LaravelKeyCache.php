<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Laravel;

use Illuminate\Contracts\Cache\Repository;
use Jw1980\Passkey\Firebase\KeyCache;

/** Google's public keys in the application's cache store, shared by all workers. */
final class LaravelKeyCache implements KeyCache
{
    private const KEY = 'passkey:firebase:google-keys';

    public function __construct(private readonly Repository $cache) {}

    public function get(): ?array
    {
        $entry = $this->cache->get(self::KEY);
        if (! is_array($entry) || ! is_int($entry['expiresAt'] ?? null) || ! is_int($entry['fetchedAt'] ?? null) || ! is_array($entry['keys'] ?? null)) {
            return null;
        }
        /** @var array<string, string> $keys */
        $keys = array_filter($entry['keys'], static fn ($pem, $kid): bool => is_string($kid) && is_string($pem), ARRAY_FILTER_USE_BOTH);

        return ['keys' => $keys, 'expiresAt' => $entry['expiresAt'], 'fetchedAt' => $entry['fetchedAt']];
    }

    public function put(array $keys, int $expiresAt, int $fetchedAt): void
    {
        $this->cache->put(self::KEY, ['keys' => $keys, 'expiresAt' => $expiresAt, 'fetchedAt' => $fetchedAt], 86400);
    }
}
