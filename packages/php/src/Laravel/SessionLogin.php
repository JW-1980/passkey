<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Laravel;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Http\Request;
use Jw1980\Passkey\AuthenticationResult;
use Jw1980\Passkey\Laravel\Contracts\CompletesLogin;
use Jw1980\Passkey\PasskeyException;
use LogicException;

/**
 * Signs the account in on the session guard and renews the session ID. Records the moment in the
 * session (`passkey.confirmed_at`) so the application can ask for a fresh passkey confirmation.
 */
final class SessionLogin implements CompletesLogin
{
    public const CONFIRMED_AT = 'passkey.confirmed_at';

    public function __construct(private readonly AuthFactory $auth) {}

    public function complete(Request $request, AuthenticationResult $result): array
    {
        $guard = $this->auth->guard(config('passkey.guard'));
        if (! $guard instanceof StatefulGuard || ! method_exists($guard, 'getProvider')) {
            throw new LogicException('SessionLogin needs a session guard; configure passkey.login for token guards.');
        }
        $user = $guard->getProvider()->retrieveById($result->userId);
        if ($user === null) {
            // The account was removed after the passkey was registered.
            throw PasskeyException::invalidPasskey();
        }
        $guard->login($user);
        $request->session()->regenerate();
        $request->session()->put(self::CONFIRMED_AT, time());

        return ['ok' => true];
    }
}
