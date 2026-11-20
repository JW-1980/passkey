<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Laravel\Events;

use Jw1980\Passkey\PasskeyException;

/**
 * A passkey request was refused. For the audit log: `refusal->errorCode` says what, and
 * `refusal->getPrevious()` holds the underlying reason, which the client never sees.
 */
final class PasskeyRejected
{
    public function __construct(public readonly PasskeyException $refusal, public readonly ?string $userId) {}
}
