<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase;

/** The public keys ID tokens are signed with. */
interface KeySource
{
    /**
     * The PEM certificate or public key for a key ID, or null when it is not a current key.
     *
     * @throws FirebaseException with code `unavailable` when no keys could be obtained
     */
    public function key(string $kid): ?string;
}
