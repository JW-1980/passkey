<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Handoff;

/** A redeemed handoff code: the account that approved, and what the app attached when it did. */
final class HandoffGrant
{
    /** @param array<string, mixed> $context */
    public function __construct(
        public readonly string $userId,
        public readonly array $context,
    ) {}
}
