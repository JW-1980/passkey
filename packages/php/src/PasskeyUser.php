<?php

declare(strict_types=1);

namespace Jw1980\Passkey;

use InvalidArgumentException;

/** The account a passkey is created for, as the passkey prompt shows it. */
final class PasskeyUser
{
    /**
     * @param  string  $id  The application's own stable account identifier. Never sent to the
     *                      authenticator: it gets an opaque handle derived from it.
     * @param  string  $name  What tells accounts apart in the passkey picker (an e-mail address).
     * @param  string  $displayName  The person's name.
     */
    public function __construct(
        public readonly string $id,
        public readonly string $name,
        public readonly string $displayName,
    ) {
        if ($id === '' || strlen($id) > 191) {
            throw new InvalidArgumentException('The account identifier must be 1 to 191 bytes.');
        }
        if (trim($name) === '' || trim($displayName) === '') {
            throw new InvalidArgumentException('The account needs a name and a display name.');
        }
    }
}
