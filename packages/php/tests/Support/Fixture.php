<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Tests\Support;

use Jw1980\Passkey\PasskeyServer;
use Jw1980\Passkey\PasskeyUser;
use Jw1980\Passkey\RelyingParty;
use Jw1980\Passkey\Storage\PdoChallengeStore;
use Jw1980\Passkey\Storage\PdoCredentialStore;
use Jw1980\Passkey\Storage\Schema;
use PDO;
use Symfony\Component\Clock\MockClock;

/** A passkey server on a fresh database (in-memory SQLite by default) with a clock the test moves. */
final class Fixture
{
    public const ORIGIN = 'https://app.example';

    public const SECRET = 'test-user-handle-secret-of-32-bytes!!';

    public readonly PDO $pdo;

    public readonly MockClock $clock;

    public readonly PdoCredentialStore $credentials;

    public readonly PdoChallengeStore $challenges;

    public readonly PasskeyServer $server;

    /** @param list<string> $origins */
    public function __construct(array $origins = [self::ORIGIN], int $maxPasskeys = 10)
    {
        // PASSKEY_TEST_DSN (with PASSKEY_TEST_USER and PASSKEY_TEST_PASSWORD) runs the same tests on
        // a MySQL or MariaDB server instead of in-memory SQLite. Its passkey tables are dropped.
        $dsn = getenv('PASSKEY_TEST_DSN');
        if (is_string($dsn) && $dsn !== '') {
            $this->pdo = new PDO($dsn, (string) getenv('PASSKEY_TEST_USER'), (string) getenv('PASSKEY_TEST_PASSWORD'));
            $this->pdo->exec('DROP TABLE IF EXISTS passkeys');
            $this->pdo->exec('DROP TABLE IF EXISTS passkey_challenges');
            $driver = 'mysql';
        } else {
            $this->pdo = new PDO('sqlite::memory:');
            $driver = 'sqlite';
        }
        foreach (Schema::statements($driver) as $statement) {
            $this->pdo->exec($statement);
        }
        $this->clock = new MockClock('2026-11-20 10:00:00', 'UTC');
        $this->credentials = new PdoCredentialStore($this->pdo);
        $this->challenges = new PdoChallengeStore($this->pdo, clock: $this->clock);
        $this->server = new PasskeyServer(
            new RelyingParty('app.example', 'Example App', $origins),
            $this->credentials,
            $this->challenges,
            self::SECRET,
            ceremonyTtlSeconds: 300,
            maxPasskeysPerUser: $maxPasskeys,
            clock: $this->clock,
        );
    }

    public static function user(string $id = 'user-1'): PasskeyUser
    {
        return new PasskeyUser($id, "{$id}@example.com", "Person {$id}");
    }

    /** Registers a new software passkey for the account and returns it. */
    public function enroll(string $userId = 'user-1', int $flags = SoftPasskey::UP | SoftPasskey::UV): SoftPasskey
    {
        $device = new SoftPasskey;
        $ceremony = $this->server->beginRegistration(self::user($userId));
        $this->server->finishRegistration($ceremony->id, $device->register($ceremony->publicKey, self::ORIGIN, $flags), self::user($userId));

        return $device;
    }
}
