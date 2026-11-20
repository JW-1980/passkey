<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Laravel\Contracts;

use Illuminate\Http\Request;
use Jw1980\Passkey\AuthenticationResult;
use Jw1980\Passkey\PasskeyException;
use Symfony\Component\HttpFoundation\Response;

/** Decides what a verified passkey sign-in leads to: a session, a token, or a next step. */
interface CompletesLogin
{
    /**
     * @return array<string, mixed>|Response The answer to the client; an array is sent as JSON.
     *
     * @throws PasskeyException to refuse (for example {@see PasskeyException::invalidPasskey()} for
     *                          an account that may no longer sign in)
     */
    public function complete(Request $request, AuthenticationResult $result): array|Response;
}
