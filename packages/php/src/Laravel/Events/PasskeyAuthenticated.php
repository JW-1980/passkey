<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Laravel\Events;

use Jw1980\Passkey\AuthenticationResult;

/** A passkey sign-in was verified (before the application completed the sign-in). */
final class PasskeyAuthenticated
{
    public function __construct(public readonly AuthenticationResult $result) {}
}
