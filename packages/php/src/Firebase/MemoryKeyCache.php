<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase;

/** Keeps the keys for the life of the PHP process (long-running workers, tests). */
final class MemoryKeyCache implements KeyCache
{
    /** @var array{keys: array<string, string>, expiresAt: int}|null */
    private ?array $entry = null;

    public function get(): ?array
    {
        return $this->entry;
    }

    public function put(array $keys, int $expiresAt): void
    {
        $this->entry = ['keys' => $keys, 'expiresAt' => $expiresAt];
    }
}
