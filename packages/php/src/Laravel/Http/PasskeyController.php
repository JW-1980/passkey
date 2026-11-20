<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Laravel\Http;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Factory as AuthFactory;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response as HttpResponse;
use Jw1980\Passkey\Laravel\Contracts\CompletesLogin;
use Jw1980\Passkey\Laravel\Contracts\ResolvesPasskeyUser;
use Jw1980\Passkey\Laravel\Events\PasskeyAuthenticated;
use Jw1980\Passkey\Laravel\Events\PasskeyDeleted;
use Jw1980\Passkey\Laravel\Events\PasskeyRegistered;
use Jw1980\Passkey\Laravel\Events\PasskeyRejected;
use Jw1980\Passkey\PasskeyException;
use Jw1980\Passkey\PasskeyServer;
use Jw1980\Passkey\PasskeyUser;
use Jw1980\Passkey\StoredPasskey;
use Symfony\Component\HttpFoundation\Response;

final class PasskeyController
{
    public function __construct(
        private readonly PasskeyServer $server,
        private readonly ResolvesPasskeyUser $users,
        private readonly CompletesLogin $login,
        private readonly AuthFactory $auth,
        private readonly Dispatcher $events,
    ) {}

    public function registerOptions(Request $request): JsonResponse
    {
        return $this->guarded($request, fn (): JsonResponse => new JsonResponse(
            $this->server->beginRegistration($this->passkeyUser($request))->toArray(),
        ));
    }

    public function registerVerify(Request $request): JsonResponse
    {
        return $this->guarded($request, function () use ($request): JsonResponse {
            $name = $request->input('name');
            if ($name !== null && ! is_string($name)) {
                throw PasskeyException::invalidRequest('The passkey name must be text.');
            }
            $passkey = $this->server->finishRegistration(
                self::ceremony($request),
                self::credential($request),
                $this->passkeyUser($request),
                $name,
            );
            $this->events->dispatch(new PasskeyRegistered($passkey));

            return new JsonResponse(['passkey' => $passkey->toSummary()], 201);
        });
    }

    public function loginOptions(Request $request): JsonResponse
    {
        // Someone who is already signed in can only confirm with a passkey of that account.
        return $this->guarded($request, fn (): JsonResponse => new JsonResponse(
            $this->server->beginAuthentication($this->userId($request))->toArray(),
        ));
    }

    public function loginVerify(Request $request): Response
    {
        return $this->guarded($request, function () use ($request): Response {
            $result = $this->server->finishAuthentication(self::ceremony($request), self::credential($request));
            $this->events->dispatch(new PasskeyAuthenticated($result));
            $answer = $this->login->complete($request, $result);

            return is_array($answer) ? new JsonResponse($answer) : $answer;
        });
    }

    public function index(Request $request): JsonResponse
    {
        return new JsonResponse(['passkeys' => array_map(
            static fn (StoredPasskey $passkey): array => $passkey->toSummary(),
            $this->server->passkeys($this->passkeyUser($request)->id),
        )]);
    }

    public function update(Request $request, string $passkey): JsonResponse
    {
        return $this->guarded($request, function () use ($request, $passkey): JsonResponse {
            $name = $request->input('name');
            if (! is_string($name)) {
                throw PasskeyException::invalidRequest('The passkey name must be text.');
            }

            return new JsonResponse(['passkey' => $this->server->rename($this->passkeyUser($request)->id, $passkey, $name)->toSummary()]);
        });
    }

    public function destroy(Request $request, string $passkey): Response
    {
        return $this->guarded($request, function () use ($request, $passkey): Response {
            $userId = $this->passkeyUser($request)->id;
            $this->server->delete($userId, $passkey);
            $this->events->dispatch(new PasskeyDeleted($userId, $passkey));

            return new HttpResponse(status: 204);
        });
    }

    /**
     * @template T of Response
     *
     * @param  Closure(): T  $action
     * @return T
     */
    private function guarded(Request $request, Closure $action): Response
    {
        try {
            return $action();
        } catch (PasskeyException $refusal) {
            $this->events->dispatch(new PasskeyRejected($refusal, $this->userId($request)));
            throw $refusal;
        }
    }

    private function account(Request $request): ?Authenticatable
    {
        return $this->auth->guard(config('passkey.guard'))->user();
    }

    private function userId(Request $request): ?string
    {
        $account = $this->account($request);

        return $account === null ? null : $this->users->resolve($account)->id;
    }

    private function passkeyUser(Request $request): PasskeyUser
    {
        $account = $this->account($request);
        if ($account === null) {
            // The auth middleware is misconfigured: refuse rather than act for nobody.
            abort(401);
        }

        return $this->users->resolve($account);
    }

    private static function ceremony(Request $request): string
    {
        $ceremony = $request->input('ceremony');
        if (! is_string($ceremony) || $ceremony === '') {
            throw PasskeyException::invalidRequest('The passkey request is incomplete.');
        }

        return $ceremony;
    }

    /** @return array<array-key, mixed> */
    private static function credential(Request $request): array
    {
        $credential = $request->input('credential');
        if (! is_array($credential)) {
            throw PasskeyException::invalidRequest('The passkey request is incomplete.');
        }

        return $credential;
    }
}
