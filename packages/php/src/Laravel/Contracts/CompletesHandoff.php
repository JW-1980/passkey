<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Laravel\Contracts;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Http\Request;
use Jw1980\Passkey\Handoff\HandoffGrant;
use Jw1980\Passkey\PasskeyException;

/** The application's part of the desktop sign-in handoff. */
interface CompletesHandoff
{
    /**
     * Called when the browser page asks for a code. Refuse here when the browser session is not
     * strong enough to hand over (for example: no second factor yet).
     *
     * @return array<string, mixed> Context stored with the code and returned at the exchange.
     *
     * @throws PasskeyException to refuse
     */
    public function approve(Request $request, Authenticatable $user): array;

    /**
     * Called when the desktop app redeemed its code: issue its session.
     *
     * @return array<string, mixed> The answer to the desktop app, for example a token and its expiry.
     */
    public function complete(Request $request, HandoffGrant $grant): array;
}
