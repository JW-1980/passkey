<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Laravel;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Debug\ExceptionHandler;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\DatabaseManager;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Router;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Jw1980\Passkey\Contracts\ChallengeStore;
use Jw1980\Passkey\Contracts\CredentialStore;
use Jw1980\Passkey\Firebase\AdminClient;
use Jw1980\Passkey\Firebase\CustomTokenIssuer;
use Jw1980\Passkey\Firebase\FileKeyCache;
use Jw1980\Passkey\Firebase\FirebaseException;
use Jw1980\Passkey\Firebase\FirebasePasskeys;
use Jw1980\Passkey\Firebase\GoogleKeySource;
use Jw1980\Passkey\Firebase\Http\AuthHub;
use Jw1980\Passkey\Firebase\IdTokenVerifier;
use Jw1980\Passkey\Firebase\ProjectId;
use Jw1980\Passkey\Firebase\ServiceAccount;
use Jw1980\Passkey\Handoff\HandoffServer;
use Jw1980\Passkey\Laravel\Contracts\CompletesHandoff;
use Jw1980\Passkey\Laravel\Contracts\CompletesLogin;
use Jw1980\Passkey\Laravel\Contracts\ResolvesPasskeyUser;
use Jw1980\Passkey\Laravel\Http\Middleware\VerifyFirebaseToken;
use Jw1980\Passkey\PasskeyException;
use Jw1980\Passkey\PasskeyServer;
use Jw1980\Passkey\RelyingParty;
use Jw1980\Passkey\Storage\PdoChallengeStore;
use Jw1980\Passkey\Storage\PdoCredentialStore;
use Jw1980\Passkey\WellKnown;
use LogicException;
use PDO;

final class PasskeyServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../../config/passkey.php', 'passkey');

        $this->app->singleton(RelyingParty::class, static function (Application $app): RelyingParty {
            $config = (array) self::config($app)->get('passkey.relying_party');
            $url = (string) self::config($app)->get('app.url');
            $origins = array_values((array) ($config['origins'] ?? []));
            if ($origins === []) {
                $origins = [$url];
            }
            foreach ((array) self::config($app)->get('passkey.android.fingerprints') as $fingerprint) {
                $origins[] = WellKnown::androidOrigin((string) $fingerprint);
            }
            $id = $config['id'] ?? null;

            return new RelyingParty(
                is_string($id) && $id !== '' ? $id : strtolower((string) parse_url($url, PHP_URL_HOST)),
                (string) ($config['name'] ?? self::config($app)->get('app.name')),
                $origins,
                array_values(array_map('strval', (array) ($config['related_origins'] ?? []))),
            );
        });

        $this->app->singleton(CredentialStore::class, static fn (Application $app): CredentialStore => new PdoCredentialStore(
            self::pdo($app), self::table($app, 'passkeys'),
        ));
        $this->app->singleton(ChallengeStore::class, static fn (Application $app): ChallengeStore => new PdoChallengeStore(
            self::pdo($app), self::table($app, 'challenges'),
        ));

        $this->app->singleton(PasskeyServer::class, static fn (Application $app): PasskeyServer => new PasskeyServer(
            $app->make(RelyingParty::class),
            $app->make(CredentialStore::class),
            $app->make(ChallengeStore::class),
            self::userHandleSecret($app),
            (int) self::config($app)->get('passkey.ceremony_ttl'),
            (int) self::config($app)->get('passkey.max_passkeys'),
        ));

        $this->app->singleton(HandoffServer::class, static fn (Application $app): HandoffServer => new HandoffServer(
            $app->make(ChallengeStore::class),
            (string) self::config($app)->get('passkey.handoff.callback_path'),
            (int) self::config($app)->get('passkey.handoff.code_ttl'),
        ));

        $this->registerFirebase();

        $this->app->bind(ResolvesPasskeyUser::class, static fn (Application $app) => $app->make((string) self::config($app)->get('passkey.user_resolver')));
        $this->app->bind(CompletesLogin::class, static fn (Application $app) => $app->make((string) self::config($app)->get('passkey.login')));
        $this->app->bind(CompletesHandoff::class, static function (Application $app) {
            $completer = self::config($app)->get('passkey.handoff.completer');
            if (! is_string($completer) || $completer === '') {
                throw new LogicException('The desktop handoff is enabled without passkey.handoff.completer.');
            }

            return $app->make($completer);
        });
    }

    public function boot(): void
    {
        $this->publishes([__DIR__.'/../../config/passkey.php' => $this->app->configPath('passkey.php')], 'passkey-config');
        $this->publishesMigrations([__DIR__.'/../../database/migrations' => $this->app->databasePath('migrations')], 'passkey-migrations');
        if (config('passkey.load_migrations') !== false) {
            $this->loadMigrationsFrom(__DIR__.'/../../database/migrations');
        }

        RateLimiter::for('passkey', static fn (Request $request): Limit => Limit::perMinute(
            max(1, (int) config('passkey.rate_limit')),
        )->by((string) $request->ip()));

        $handler = $this->app->make(ExceptionHandler::class);
        if (method_exists($handler, 'renderable')) {
            $handler->renderable(static fn (PasskeyException $refusal): JsonResponse => new JsonResponse($refusal->toArray(), $refusal->httpStatus));
        }
        if (method_exists($handler, 'dontReport')) {
            // A refusal is an answer, not a fault; applications audit them through PasskeyRejected.
            $handler->dontReport(PasskeyException::class);
        }

        if (method_exists($handler, 'renderable')) {
            $handler->renderable(static function (FirebaseException $refusal): JsonResponse {
                if ($refusal->errorCode === FirebaseException::CONFIGURATION) {
                    error_log('passkey: Firebase configuration error: '.$refusal->getMessage());
                }

                return new JsonResponse($refusal->toArray(), $refusal->httpStatus);
            });
        }
        $this->app->make(Router::class)->aliasMiddleware('firebase', VerifyFirebaseToken::class);

        if (config('passkey.routes.enabled') === true) {
            $this->loadRoutesFrom(__DIR__.'/../../routes/'.(config('passkey.firebase.enabled') === true ? 'firebase.php' : 'passkey.php'));
        }
    }

    /**
     * Firebase mode (docs/functional-design.md). The verifier and the middleware are available
     * whenever a project ID is set, so that any Laravel application can verify ID tokens; the hub
     * itself needs `passkey.firebase.enabled`.
     */
    private function registerFirebase(): void
    {
        $emulator = static function (Application $app): ?string {
            $host = self::config($app)->get('passkey.firebase.emulator_host');

            return is_string($host) && $host !== '' && ProjectId::isDemo(self::projectId($app)) ? $host : null;
        };

        $this->app->singleton(IdTokenVerifier::class, static function (Application $app) use ($emulator): IdTokenVerifier {
            $project = self::projectId($app);
            if ($emulator($app) !== null) {
                return IdTokenVerifier::forEmulator($project);
            }
            $cache = self::config($app)->get('passkey.firebase.key_cache');

            return IdTokenVerifier::forProject($project, new GoogleKeySource(
                cache: is_string($cache) && $cache !== '' ? new FileKeyCache($cache) : new LaravelKeyCache($app->make(\Illuminate\Contracts\Cache\Repository::class)),
            ));
        });

        $this->app->singleton(ServiceAccount::class, static function (Application $app) use ($emulator): ServiceAccount {
            $path = self::config($app)->get('passkey.firebase.credentials');
            if (is_string($path) && $path !== '') {
                $account = ServiceAccount::fromFile($path);
                if ($account->projectId !== self::projectId($app)) {
                    throw FirebaseException::configuration('FIREBASE_CREDENTIALS belongs to another project than FIREBASE_PROJECT_ID.');
                }

                return $account;
            }
            if ($emulator($app) !== null) {
                return ServiceAccount::forEmulator(self::projectId($app));
            }
            throw FirebaseException::configuration('Set FIREBASE_CREDENTIALS to the service account JSON file.');
        });

        $this->app->singleton(AdminClient::class, static function (Application $app) use ($emulator): AdminClient {
            $host = $emulator($app);

            return $host !== null
                ? AdminClient::forEmulator(self::projectId($app), $host)
                : AdminClient::forServiceAccount($app->make(ServiceAccount::class));
        });

        $this->app->singleton(VerifyFirebaseToken::class, static function (Application $app): VerifyFirebaseToken {
            $hasAdmin = self::config($app)->get('passkey.firebase.credentials') || self::config($app)->get('passkey.firebase.emulator_host');

            return new VerifyFirebaseToken($app->make(IdTokenVerifier::class), $hasAdmin ? $app->make(AdminClient::class) : null);
        });

        $this->app->singleton(FirebasePasskeys::class, static fn (Application $app): FirebasePasskeys => new FirebasePasskeys(
            $app->make(PasskeyServer::class),
            $app->make(HandoffServer::class),
            new CustomTokenIssuer($app->make(ServiceAccount::class), (int) self::config($app)->get('passkey.firebase.custom_token_ttl')),
            $app->make(IdTokenVerifier::class),
            self::config($app)->get('passkey.firebase.check_user_exists') === true ? $app->make(AdminClient::class) : null,
            (int) self::config($app)->get('passkey.firebase.recent_sign_in'),
        ));

        $this->app->singleton(AuthHub::class, static fn (Application $app): AuthHub => new AuthHub(
            $app->make(FirebasePasskeys::class),
            '/'.trim((string) self::config($app)->get('passkey.routes.prefix'), '/'),
            array_values(array_map('strval', (array) self::config($app)->get('passkey.firebase.cors_origins'))),
            new LaravelRateLimiter($app->make(\Illuminate\Cache\RateLimiter::class)),
            max(1, (int) self::config($app)->get('passkey.rate_limit')),
        ));
    }

    private static function projectId(Application $app): string
    {
        $project = self::config($app)->get('passkey.firebase.project_id');
        if (! is_string($project) || ! ProjectId::isValid($project)) {
            throw FirebaseException::configuration('Set FIREBASE_PROJECT_ID to the Firebase project ID.');
        }

        return $project;
    }

    private static function config(Application $app): Repository
    {
        return $app->make(Repository::class);
    }

    /** @return \Closure(): PDO */
    private static function pdo(Application $app): \Closure
    {
        return static fn (): PDO => $app->make(DatabaseManager::class)
            ->connection(self::config($app)->get('passkey.connection'))
            ->getPdo();
    }

    private static function table(Application $app, string $which): string
    {
        $prefix = $app->make(DatabaseManager::class)->connection(self::config($app)->get('passkey.connection'))->getTablePrefix();

        return $prefix.self::config($app)->get("passkey.tables.{$which}");
    }

    private static function userHandleSecret(Application $app): string
    {
        $secret = self::config($app)->get('passkey.user_handle_secret');
        if (is_string($secret) && $secret !== '') {
            return $secret;
        }
        $key = (string) self::config($app)->get('app.key');
        if ($key === '') {
            throw new LogicException('Set PASSKEY_USER_HANDLE_SECRET or APP_KEY.');
        }

        return hash_hmac('sha256', 'passkey-user-handle-secret', $key);
    }
}
