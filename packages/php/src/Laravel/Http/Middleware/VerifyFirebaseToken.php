<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Laravel\Http\Middleware;

use Closure;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Jw1980\Passkey\Firebase\AdminClient;
use Jw1980\Passkey\Firebase\FirebaseException;
use Jw1980\Passkey\Firebase\FirebaseIdentity;
use Jw1980\Passkey\Firebase\IdTokenVerifier;
use Symfony\Component\HttpFoundation\Response;

/**
 * Route middleware `firebase`: requires `Authorization: Bearer <Firebase ID token>` and puts the
 * verified {@see FirebaseIdentity} in the request attribute `firebase`. Use it on the route where a
 * client exchanges its ID token for the application's own session.
 *
 * Options, comma separated after the alias: `mfa` (multi-factor sign-in required), `recent=<s>`
 * (signed in at most s seconds ago), `active` (ask Firebase whether the user still exists, is enabled
 * and was not revoked; one call to Google).
 *
 * Example: `->middleware('firebase:mfa,recent=300,active')`.
 */
final class VerifyFirebaseToken
{
    public const ATTRIBUTE = 'firebase';

    public function __construct(
        private readonly IdTokenVerifier $verifier,
        private readonly ?AdminClient $admin = null,
    ) {}

    public function handle(Request $request, Closure $next, string ...$options): Response
    {
        try {
            $header = (string) $request->headers->get('Authorization', '');
            if (preg_match('/^Bearer ([A-Za-z0-9._-]+)$/', trim($header), $match) !== 1) {
                throw FirebaseException::invalidToken('no bearer token');
            }
            $identity = $this->verifier->verify($match[1]);
            foreach ($options as $option) {
                if ($option === 'mfa' && ! $identity->isMultiFactor()) {
                    return new JsonResponse(['error' => ['code' => 'mfa_required', 'message' => 'Sign in with a passkey or a second factor.']], 403);
                }
                if (str_starts_with($option, 'recent=') && ! $identity->isRecent((int) substr($option, 7))) {
                    throw FirebaseException::reauthenticationRequired();
                }
                if ($option === 'active') {
                    if ($this->admin === null) {
                        throw FirebaseException::configuration('The "active" check needs Firebase credentials.');
                    }
                    if (! $this->admin->isActive($identity)) {
                        throw FirebaseException::invalidToken('revoked, disabled or deleted');
                    }
                }
            }
        } catch (FirebaseException $refusal) {
            return new JsonResponse($refusal->toArray(), $refusal->httpStatus,
                $refusal->httpStatus === 401 ? ['WWW-Authenticate' => 'Bearer', 'Cache-Control' => 'no-store'] : ['Cache-Control' => 'no-store']);
        }
        $request->attributes->set(self::ATTRIBUTE, $identity);

        return $next($request);
    }
}
