<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Contracts;

/** Short-lived, single-use server state: WebAuthn challenges and handoff codes. */
interface ChallengeStore
{
    public function put(string $key, string $payload, int $ttlSeconds): void;

    /**
     * Returns the payload and removes it in one step, so two requests can never both receive it.
     * Null when the key is unknown, already used or expired.
     */
    public function pull(string $key): ?string;
}
