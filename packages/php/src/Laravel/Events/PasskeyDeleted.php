<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Laravel\Events;

/** A passkey was removed from an account. `passkeyId` is the credential ID (base64url). */
final class PasskeyDeleted
{
    public function __construct(public readonly string $userId, public readonly string $passkeyId) {}
}
