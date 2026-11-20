<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Laravel\Http;

use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Jw1980\Passkey\Handoff\HandoffServer;
use Jw1980\Passkey\Laravel\Contracts\CompletesHandoff;
use Jw1980\Passkey\Laravel\Contracts\ResolvesPasskeyUser;
use Jw1980\Passkey\PasskeyException;

final class HandoffController
{
    public function __construct(
        private readonly HandoffServer $handoff,
        private readonly CompletesHandoff $completer,
        private readonly ResolvesPasskeyUser $users,
        private readonly AuthFactory $auth,
    ) {}

    /** Browser page, signed in: issue a code for the desktop app. */
    public function authorize(Request $request): JsonResponse
    {
        $account = $this->auth->guard(config('passkey.guard'))->user();
        if ($account === null) {
            abort(401);
        }
        $challenge = $request->input('challenge');
        $port = $request->input('port');
        $state = $request->input('state');
        if (! is_string($challenge) || ! is_string($state) || ! is_int($port)) {
            throw PasskeyException::invalidRequest('The sign-in handoff request is not valid.');
        }
        $context = $this->completer->approve($request, $account);

        return new JsonResponse([
            'redirect' => $this->handoff->authorize($this->users->resolve($account)->id, $challenge, $port, $state, $context),
        ]);
    }

    /** Desktop app: redeem the code. */
    public function exchange(Request $request): JsonResponse
    {
        $code = $request->input('code');
        $verifier = $request->input('code_verifier');
        if (! is_string($code) || ! is_string($verifier)) {
            throw PasskeyException::invalidHandoff();
        }

        $response = new JsonResponse($this->completer->complete($request, $this->handoff->exchange($code, $verifier)));
        $response->headers->set('Cache-Control', 'no-store');

        return $response;
    }
}
