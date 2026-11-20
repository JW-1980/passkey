<?php

declare(strict_types=1);

namespace Jw1980\Passkey;

/** A started registration or sign-in: what the server sends to the client. */
final class Ceremony
{
    /** @param array<string, mixed> $publicKey WebAuthn options in their JSON form. */
    public function __construct(
        public readonly string $id,
        public readonly array $publicKey,
    ) {}

    /** @return array{ceremony: string, publicKey: array<string, mixed>} */
    public function toArray(): array
    {
        return ['ceremony' => $this->id, 'publicKey' => $this->publicKey];
    }
}
