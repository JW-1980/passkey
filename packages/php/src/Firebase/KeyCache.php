<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase;

/**
 * Where Google's public keys are kept between requests, shared by all processes of the server.
 *
 * This is a **trust anchor**: whoever can write it can make forged ID tokens verify. Keep it in
 * storage only the application can write (its own cache store, or a private directory).
 */
interface KeyCache
{
    /**
     * @return array{keys: array<string, string>, expiresAt: int, fetchedAt: int}|null `fetchedAt` is
     *                                                                                 the last attempt to fetch, also a failed one
     */
    public function get(): ?array;

    /** @param array<string, string> $keys kid → PEM */
    public function put(array $keys, int $expiresAt, int $fetchedAt): void;
}
