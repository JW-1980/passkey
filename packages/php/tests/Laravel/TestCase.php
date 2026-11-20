<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Tests\Laravel;

use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;
use Illuminate\Testing\TestResponse;
use Jw1980\Passkey\Laravel\PasskeyServiceProvider;
use Jw1980\Passkey\Tests\Support\SoftPasskey;
use Jw1980\Passkey\Tests\Support\TestUser;
use Orchestra\Testbench\TestCase as Testbench;

abstract class TestCase extends Testbench
{
    protected const ORIGIN = 'https://app.example';

    /** @return list<class-string> */
    protected function getPackageProviders($app): array
    {
        return [PasskeyServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('app.url', self::ORIGIN);
        $app['config']->set('app.name', 'Example App');
        $app['config']->set('app.key', 'base64:'.base64_encode(str_repeat('k', 32)));
        $app['config']->set('database.default', 'testing');
        // PASSKEY_TEST_DB_DRIVER (mysql or mariadb, with PASSKEY_TEST_DB_HOST, _PORT, _DATABASE, _USER
        // and _PASSWORD) runs the same tests on a real server. All tables of that database are dropped.
        $driver = getenv('PASSKEY_TEST_DB_DRIVER');
        $app['config']->set('database.connections.testing', is_string($driver) && $driver !== '' ? [
            'driver' => $driver,
            'host' => getenv('PASSKEY_TEST_DB_HOST') ?: '127.0.0.1',
            'port' => getenv('PASSKEY_TEST_DB_PORT') ?: '3306',
            'database' => (string) getenv('PASSKEY_TEST_DB_DATABASE'),
            'username' => (string) getenv('PASSKEY_TEST_DB_USER'),
            'password' => (string) getenv('PASSKEY_TEST_DB_PASSWORD'),
            'charset' => 'utf8mb4',
            'collation' => 'utf8mb4_unicode_ci',
            'prefix' => static::tablePrefix(),
            'strict' => true,
        ] : ['driver' => 'sqlite', 'database' => ':memory:', 'prefix' => static::tablePrefix()]);
        $app['config']->set('auth.providers.users.model', TestUser::class);
        $app['config']->set('session.driver', 'array');
        $app['config']->set('cache.default', 'array');
    }

    protected static function tablePrefix(): string
    {
        return '';
    }

    protected function setUp(): void
    {
        parent::setUp();
        Schema::dropAllTables();
        Schema::create('users', function (Blueprint $table): void {
            $table->id();
            $table->string('name');
            $table->string('email')->unique();
            $table->string('password')->nullable();
        });
        $this->artisan('migrate')->run();
    }

    protected function user(string $name = 'Ada'): TestUser
    {
        return TestUser::query()->forceCreate(['name' => $name, 'email' => strtolower($name).'@example.com']);
    }

    /** Registers a software passkey for the account through the HTTP routes. */
    protected function enroll(TestUser $user, ?string $name = null): SoftPasskey
    {
        $device = new SoftPasskey;
        $options = $this->actingAs($user)->postJson('/passkey/register/options')->assertOk()->json();
        $this->actingAs($user)->postJson('/passkey/register/verify', array_filter([
            'ceremony' => $options['ceremony'],
            'credential' => $device->register($options['publicKey'], self::ORIGIN),
            'name' => $name,
        ]))->assertCreated();

        return $device;
    }

    protected function signOut(): void
    {
        $this->app['auth']->guard()->logout();
        $this->app['auth']->forgetGuards();
    }

    protected function signIn(SoftPasskey $device): TestResponse
    {
        $options = $this->postJson('/passkey/login/options')->assertOk()->json();

        return $this->postJson('/passkey/login/verify', [
            'ceremony' => $options['ceremony'],
            'credential' => $device->assert($options['publicKey'], self::ORIGIN),
        ]);
    }
}
