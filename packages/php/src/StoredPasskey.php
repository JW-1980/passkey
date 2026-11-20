<?php

declare(strict_types=1);

namespace Jw1980\Passkey;

use DateTimeImmutable;
use DateTimeZone;

/** One registered passkey: the public half only. All binary fields are raw bytes. */
final class StoredPasskey
{
    /** @param list<string> $transports */
    public function __construct(
        public readonly string $credentialId,
        public readonly string $userId,
        public readonly string $userHandle,
        public readonly string $publicKey,
        public readonly int $counter,
        public readonly array $transports,
        public readonly string $aaguid,
        public readonly bool $backupEligible,
        public readonly bool $backedUp,
        public readonly string $attestationType,
        public readonly string $name,
        public readonly DateTimeImmutable $createdAt,
        public readonly ?DateTimeImmutable $lastUsedAt,
    ) {}

    /** The credential ID as clients address it (base64url). */
    public function id(): string
    {
        return Base64Url::encode($this->credentialId);
    }

    /**
     * What a client may know about the passkey. No key material.
     *
     * @return array{id: string, name: string, createdAt: string, lastUsedAt: ?string, synced: bool, transports: list<string>}
     */
    public function toSummary(): array
    {
        $utc = new DateTimeZone('UTC');

        return [
            'id' => $this->id(),
            'name' => $this->name,
            'createdAt' => $this->createdAt->setTimezone($utc)->format('Y-m-d\TH:i:s\Z'),
            'lastUsedAt' => $this->lastUsedAt?->setTimezone($utc)->format('Y-m-d\TH:i:s\Z'),
            'synced' => $this->backupEligible,
            'transports' => $this->transports,
        ];
    }
}
