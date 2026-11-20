<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Tests\Support;

use Illuminate\Foundation\Auth\User;

/**
 * @property int $id
 * @property string $name
 * @property string $email
 */
final class TestUser extends User
{
    protected $table = 'users';

    public $timestamps = false;
}
