<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase;

/** What a client receives after the hub authenticated it: a custom token to exchange at Firebase. */
final class CustomTokenGrant
{
    public function __construct(
        public readonly string $uid,
        public readonly string $customToken,
        public readonly int $expiresIn,
    ) {}

    /** @return array{firebase: array{customToken: string, expiresIn: int}} The uid is not sent. */
    public function toArray(): array
    {
        return ['firebase' => ['customToken' => $this->customToken, 'expiresIn' => $this->expiresIn]];
    }
}
