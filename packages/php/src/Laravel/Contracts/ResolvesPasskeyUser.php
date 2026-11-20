<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Laravel\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Jw1980\Passkey\PasskeyUser;

interface ResolvesPasskeyUser
{
    public function resolve(Authenticatable $user): PasskeyUser;
}
