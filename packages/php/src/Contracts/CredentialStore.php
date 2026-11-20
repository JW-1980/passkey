<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Contracts;

use DateTimeImmutable;
use Jw1980\Passkey\PasskeyException;
use Jw1980\Passkey\StoredPasskey;

/** Where registered passkeys live. Credential IDs are raw bytes. */
interface CredentialStore
{
    public function find(string $credentialId): ?StoredPasskey;

    /** @return list<StoredPasskey> oldest first */
    public function forUser(string $userId): array;

    public function countForUser(string $userId): int;

    /** @throws PasskeyException `already_registered` when the credential ID is already stored */
    public function add(StoredPasskey $passkey): void;

    /**
     * Records a sign-in. The stored counter never goes down: when two sign-ins race, the lower
     * counter does not overwrite the higher one.
     */
    public function recordUse(string $credentialId, int $counter, bool $backedUp, DateTimeImmutable $at): void;

    /** Returns false when the account has no such passkey. */
    public function rename(string $userId, string $credentialId, string $name): bool;

    /** Returns false when the account has no such passkey. */
    public function delete(string $userId, string $credentialId): bool;
}
