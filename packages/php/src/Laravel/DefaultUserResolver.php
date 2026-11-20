<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Laravel;

use Illuminate\Contracts\Auth\Authenticatable;
use Jw1980\Passkey\Laravel\Contracts\ResolvesPasskeyUser;
use Jw1980\Passkey\PasskeyUser;

/** Uses the `email` and `name` attributes of the account where they exist. */
final class DefaultUserResolver implements ResolvesPasskeyUser
{
    public function resolve(Authenticatable $user): PasskeyUser
    {
        $id = (string) $user->getAuthIdentifier();
        $email = self::text($user, 'email') ?? $id;

        return new PasskeyUser($id, $email, self::text($user, 'name') ?? $email);
    }

    private static function text(Authenticatable $user, string $attribute): ?string
    {
        $value = $user->{$attribute} ?? null;

        return is_string($value) && trim($value) !== '' ? $value : null;
    }
}
