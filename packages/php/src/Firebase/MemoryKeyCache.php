<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase;

/**
 * Keeps the keys for the life of the PHP object. Only for long-running workers and tests: under
 * PHP-FPM every request would fetch the keys again; use {@see FileKeyCache} or the framework cache.
 */
final class MemoryKeyCache implements KeyCache
{
    /** @var array{keys: array<string, string>, expiresAt: int, fetchedAt: int}|null */
    private ?array $entry = null;

    public function get(): ?array
    {
        return $this->entry;
    }

    public function put(array $keys, int $expiresAt, int $fetchedAt): void
    {
        $this->entry = ['keys' => $keys, 'expiresAt' => $expiresAt, 'fetchedAt' => $fetchedAt];
    }
}
