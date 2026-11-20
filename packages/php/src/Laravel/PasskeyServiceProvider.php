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
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;
use Jw1980\Passkey\Contracts\ChallengeStore;
use Jw1980\Passkey\Contracts\CredentialStore;
use Jw1980\Passkey\Handoff\HandoffServer;
use Jw1980\Passkey\Laravel\Contracts\CompletesHandoff;
use Jw1980\Passkey\Laravel\Contracts\CompletesLogin;
use Jw1980\Passkey\Laravel\Contracts\ResolvesPasskeyUser;
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
        $this->loadMigrationsFrom(__DIR__.'/../../database/migrations');

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

        if (config('passkey.routes.enabled') === true) {
            $this->loadRoutesFrom(__DIR__.'/../../routes/passkey.php');
        }
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
