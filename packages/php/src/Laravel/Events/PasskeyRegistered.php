<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Laravel\Events;

use Jw1980\Passkey\StoredPasskey;

/** A passkey was added to an account. */
final class PasskeyRegistered
{
    public function __construct(public readonly StoredPasskey $passkey) {}
}
