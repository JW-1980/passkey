<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase\Http;

use InvalidArgumentException;
use JsonException;
use Jw1980\Passkey\Firebase\FirebaseException;
use Jw1980\Passkey\Firebase\FirebaseIdentity;
use Jw1980\Passkey\Firebase\FirebasePasskeys;
use Jw1980\Passkey\PasskeyException;
use Throwable;

/**
 * The auth hub's HTTP contract (`docs/protocol.md`, `docs/functional-design.md` §9) without a
 * framework: give it a {@see HubRequest}, send the {@see HubResponse}. Requests outside its paths
 * answer null, so the application can route them itself.
 *
 * Signed-in routes take the Firebase ID token in `Authorization: Bearer …` and never read cookies;
 * browsers on other listed origins may call the hub (CORS without credentials).
 */
final class AuthHub
{
    private const LIMITED = ['login/options', 'login/verify', 'handoff/exchange'];

    /** @var list<string> */
    private readonly array $allowedOrigins;

    /**
     * @param  list<string>  $allowedOrigins  Web origins (`https://host[:port]`) whose pages may call the hub.
     * @param  array<string, mixed>  $wellKnown  Path (`/.well-known/…`) → JSON document to serve.
     */
    public function __construct(
        private readonly FirebasePasskeys $passkeys,
        private readonly string $basePath = '/passkey',
        array $allowedOrigins = [],
        private readonly ?RateLimiter $limiter = null,
        private readonly int $limitPerMinute = 30,
        private readonly array $wellKnown = [],
    ) {
        if (preg_match('#^(/[A-Za-z0-9_-]+)*$#', $basePath) !== 1) {
            throw new InvalidArgumentException('The base path must look like "/passkey" (or be empty).');
        }
        foreach ($allowedOrigins as $origin) {
            if (preg_match('#^https?://[a-z0-9.-]+(:\d{1,5})?$#', $origin) !== 1) {
                throw new InvalidArgumentException("The origin '{$origin}' must be scheme://host[:port].");
            }
        }
        foreach (array_keys($wellKnown) as $path) {
            if (! str_starts_with($path, '/.well-known/')) {
                throw new InvalidArgumentException('Well-known documents must live under /.well-known/.');
            }
        }
        $this->allowedOrigins = array_values($allowedOrigins);
    }

    public function handle(HubRequest $request): ?HubResponse
    {
        if ($request->method === 'GET' && array_key_exists($request->path, $this->wellKnown)) {
            return HubResponse::json($this->wellKnown[$request->path], 200, ['Cache-Control' => 'public, max-age=3600']);
        }
        $prefix = $this->basePath.'/';
        if (! str_starts_with($request->path, $prefix)) {
            return null;
        }
        $route = substr($request->path, strlen($prefix));

        $origin = $request->header('origin');
        $cors = [];
        if ($origin !== null) {
            if (! in_array($origin, $this->allowedOrigins, true)) {
                return HubResponse::json(['error' => ['code' => 'origin_not_allowed', 'message' => 'This site may not use the sign-in service.']], 403);
            }
            $cors = ['Access-Control-Allow-Origin' => $origin, 'Vary' => 'Origin'];
        }
        if ($request->method === 'OPTIONS') {
            return new HubResponse(204, $cors + [
                'Access-Control-Allow-Methods' => 'GET, POST, PATCH, DELETE',
                'Access-Control-Allow-Headers' => 'Authorization, Content-Type',
                'Access-Control-Max-Age' => '600',
            ], '');
        }

        try {
            if ($this->limiter !== null && in_array($route, self::LIMITED, true)
                && ! $this->limiter->attempt('hub:'.$route.':'.$request->clientIp, $this->limitPerMinute, 60)) {
                return HubResponse::json(['error' => ['code' => 'too_many_requests', 'message' => 'Too many attempts. Please wait a minute.']], 429, $cors + ['Retry-After' => '60']);
            }
            $response = $this->route($request, $route);
        } catch (PasskeyException $refusal) {
            $response = HubResponse::json($refusal->toArray(), $refusal->httpStatus);
        } catch (FirebaseException $refusal) {
            if ($refusal->errorCode === FirebaseException::CONFIGURATION) {
                error_log('passkey hub: configuration error: '.$refusal->getMessage());
            }
            $response = HubResponse::json($refusal->toArray(), $refusal->httpStatus,
                $refusal->httpStatus === 401 ? ['WWW-Authenticate' => 'Bearer'] : []);
        } catch (Throwable $failure) {
            error_log('passkey hub: '.$failure::class.': '.$failure->getMessage());
            $response = HubResponse::json(['error' => ['code' => 'server', 'message' => 'Something went wrong. Please try again.']], 500);
        }

        return $response->withHeaders($cors);
    }

    private function route(HubRequest $request, string $route): HubResponse
    {
        $method = $request->method;
        if ($method === 'POST') {
            switch ($route) {
                case 'login/options':
                    return HubResponse::json($this->passkeys->beginSignIn()->toArray());
                case 'login/verify':
                    $body = self::body($request);

                    return HubResponse::json($this->passkeys->finishSignIn(self::string($body, 'ceremony'), self::object($body, 'credential'))->toArray());
                case 'register/options':
                    return HubResponse::json($this->passkeys->beginRegistration($this->identity($request))->toArray());
                case 'register/verify':
                    $identity = $this->identity($request);
                    $body = self::body($request);
                    $name = $body['name'] ?? null;
                    if ($name !== null && ! is_string($name)) {
                        throw PasskeyException::invalidRequest('The name must be text.');
                    }
                    $passkey = $this->passkeys->finishRegistration($identity, self::string($body, 'ceremony'), self::object($body, 'credential'), $name);

                    return HubResponse::json(['passkey' => $passkey->toSummary()], 201);
                case 'handoff/authorize':
                    $identity = $this->identity($request);
                    $body = self::body($request);
                    $port = $body['port'] ?? null;
                    if (! is_int($port)) {
                        throw PasskeyException::invalidRequest('The port must be a number.');
                    }
                    $redirect = $this->passkeys->authorizeHandoff($identity, self::string($body, 'challenge'), $port, self::string($body, 'state'));

                    return HubResponse::json(['redirect' => $redirect]);
                case 'handoff/exchange':
                    $body = self::body($request);

                    return HubResponse::json($this->passkeys->exchangeHandoff(self::string($body, 'code'), self::string($body, 'code_verifier'))->toArray());
            }
        }
        if ($route === 'passkeys' && $method === 'GET') {
            $identity = $this->identity($request);

            return HubResponse::json(['passkeys' => array_map(static fn ($p) => $p->toSummary(), $this->passkeys->passkeys($identity))]);
        }
        if (preg_match('#^passkeys/([A-Za-z0-9_-]{1,1400})$#', $route, $match) === 1) {
            if ($method === 'PATCH') {
                $identity = $this->identity($request);
                $passkey = $this->passkeys->rename($identity, $match[1], self::string(self::body($request), 'name'));

                return HubResponse::json(['passkey' => $passkey->toSummary()]);
            }
            if ($method === 'DELETE') {
                $this->passkeys->delete($this->identity($request), $match[1]);

                return new HubResponse(204, ['Cache-Control' => 'no-store'], '');
            }
        }

        return HubResponse::json(['error' => ['code' => 'not_found', 'message' => 'Unknown sign-in route.']], 404);
    }

    private function identity(HubRequest $request): FirebaseIdentity
    {
        return $this->passkeys->identify($request->header('authorization'));
    }

    /** @return array<string, mixed> */
    private static function body(HubRequest $request): array
    {
        try {
            $data = json_decode($request->body === '' ? '{}' : $request->body, true, 64, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            throw PasskeyException::invalidRequest('The body must be JSON.');
        }
        if (! is_array($data) || (array_is_list($data) && $data !== [])) {
            throw PasskeyException::invalidRequest('The body must be a JSON object.');
        }

        /** @var array<string, mixed> $data */
        return $data;
    }

    /** @param array<string, mixed> $body */
    private static function string(array $body, string $field): string
    {
        $value = $body[$field] ?? null;
        if (! is_string($value) || $value === '') {
            throw PasskeyException::invalidRequest("The field '{$field}' is required.");
        }

        return $value;
    }

    /**
     * @param  array<string, mixed>  $body
     * @return array<array-key, mixed>
     */
    private static function object(array $body, string $field): array
    {
        $value = $body[$field] ?? null;
        if (! is_array($value)) {
            throw PasskeyException::invalidRequest("The field '{$field}' is required.");
        }

        return $value;
    }
}
