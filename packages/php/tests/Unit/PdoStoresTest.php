<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Tests\Unit;

use DateTimeImmutable;
use InvalidArgumentException;
use Jw1980\Passkey\PasskeyException;
use Jw1980\Passkey\Storage\PdoChallengeStore;
use Jw1980\Passkey\Storage\PdoCredentialStore;
use Jw1980\Passkey\Storage\Schema;
use Jw1980\Passkey\StoredPasskey;
use Jw1980\Passkey\Tests\Support\Fixture;
use LogicException;
use PDO;
use PHPUnit\Framework\TestCase;

final class PdoStoresTest extends TestCase
{
    private Fixture $fixture;

    protected function setUp(): void
    {
        $this->fixture = new Fixture;
    }

    private function passkey(string $credentialId, string $userId = 'user-1', string $created = '2026-11-20 10:00:00'): StoredPasskey
    {
        return new StoredPasskey(
            $credentialId, $userId, str_repeat("\x02", 32), "\xa5binary\x00key", 0, ['usb'],
            '00000000-0000-0000-0000-000000000000', false, false, 'none', 'Key', new DateTimeImmutable($created.' UTC'), null,
        );
    }

    public function test_a_passkey_round_trips_with_binary_values(): void
    {
        $id = "\x00\xff".random_bytes(1021); // The longest credential ID WebAuthn allows.
        $this->fixture->credentials->add($this->passkey($id));

        $found = $this->fixture->credentials->find($id);
        self::assertEquals($this->passkey($id), $found);
        self::assertNull($this->fixture->credentials->find('other'));
    }

    public function test_a_duplicate_credential_is_refused(): void
    {
        $this->fixture->credentials->add($this->passkey('same'));

        try {
            $this->fixture->credentials->add($this->passkey('same', 'user-2'));
            self::fail('Expected a refusal.');
        } catch (PasskeyException $refusal) {
            self::assertSame(PasskeyException::ALREADY_REGISTERED, $refusal->errorCode);
        }
        self::assertSame(0, $this->fixture->credentials->countForUser('user-2'));
    }

    public function test_passkeys_are_listed_per_account_oldest_first(): void
    {
        $this->fixture->credentials->add($this->passkey('newer', created: '2026-11-20 12:00:00'));
        $this->fixture->credentials->add($this->passkey('older', created: '2026-11-19 12:00:00'));
        $this->fixture->credentials->add($this->passkey('theirs', 'user-2'));

        $ids = array_map(static fn (StoredPasskey $p): string => $p->credentialId, $this->fixture->credentials->forUser('user-1'));
        self::assertSame(['older', 'newer'], $ids);
        self::assertSame(2, $this->fixture->credentials->countForUser('user-1'));
        self::assertSame(1, $this->fixture->credentials->countForUser('user-2'));
    }

    public function test_the_counter_never_goes_down(): void
    {
        $this->fixture->credentials->add($this->passkey('key'));
        $this->fixture->credentials->recordUse('key', 7, true, new DateTimeImmutable('2026-11-21 08:00:00 UTC'));
        $this->fixture->credentials->recordUse('key', 5, false, new DateTimeImmutable('2026-11-21 09:00:00+01:00'));

        $found = $this->fixture->credentials->find('key');
        self::assertSame(7, $found?->counter);
        self::assertFalse($found->backedUp);
        self::assertSame('2026-11-21T08:00:00Z', $found->toSummary()['lastUsedAt']);
    }

    public function test_rename_and_delete_need_the_owner(): void
    {
        $this->fixture->credentials->add($this->passkey('key'));

        self::assertFalse($this->fixture->credentials->rename('user-2', 'key', 'Stolen'));
        self::assertFalse($this->fixture->credentials->delete('user-2', 'key'));
        self::assertSame('Key', $this->fixture->credentials->find('key')?->name);

        self::assertTrue($this->fixture->credentials->rename('user-1', 'key', 'Renamed'));
        self::assertSame('Renamed', $this->fixture->credentials->find('key')?->name);
        self::assertTrue($this->fixture->credentials->delete('user-1', 'key'));
        self::assertFalse($this->fixture->credentials->delete('user-1', 'key'));
    }

    public function test_a_challenge_is_returned_once(): void
    {
        $this->fixture->challenges->put('key', 'payload', 60);

        self::assertNull($this->fixture->challenges->pull('other'));
        self::assertSame('payload', $this->fixture->challenges->pull('key'));
        self::assertNull($this->fixture->challenges->pull('key'));
    }

    public function test_a_challenge_expires_and_expired_rows_are_cleared(): void
    {
        $this->fixture->challenges->put('old', 'payload', 60);
        $this->fixture->clock->sleep(59);
        $this->fixture->challenges->put('fresh', 'payload', 60);
        self::assertSame(2, (int) $this->fixture->pdo->query('SELECT COUNT(*) FROM passkey_challenges')->fetchColumn());

        $this->fixture->clock->sleep(1);
        self::assertNull($this->fixture->challenges->pull('old'));

        $this->fixture->challenges->put('old-2', 'payload', 1);
        $this->fixture->clock->sleep(120);
        $this->fixture->challenges->put('newest', 'payload', 60);
        self::assertSame(1, (int) $this->fixture->pdo->query('SELECT COUNT(*) FROM passkey_challenges')->fetchColumn());
    }

    public function test_the_store_never_holds_the_key_itself(): void
    {
        $this->fixture->challenges->put('secret-ceremony-id', 'payload', 60);

        $rows = $this->fixture->pdo->query('SELECT key_hash FROM passkey_challenges')->fetchAll(PDO::FETCH_COLUMN);
        self::assertSame([hash('sha256', 'secret-ceremony-id')], $rows);
    }

    public function test_the_connection_may_be_resolved_lazily(): void
    {
        $calls = 0;
        $store = new PdoCredentialStore(function () use (&$calls): PDO {
            $calls++;

            return $this->fixture->pdo;
        });
        self::assertSame(0, $calls);
        self::assertSame(0, $store->countForUser('user-1'));
        self::assertSame(1, $calls);
    }

    public function test_unsafe_table_names_and_silent_connections_are_refused(): void
    {
        foreach (['passkeys; DROP TABLE users', 'pass keys', '', '1table'] as $table) {
            try {
                new PdoCredentialStore($this->fixture->pdo, $table);
                self::fail("'{$table}' must be refused.");
            } catch (InvalidArgumentException) {
                $this->addToAssertionCount(1);
            }
        }
        $this->expectException(InvalidArgumentException::class);
        Schema::statements('sqlite', 'bad name');
    }

    public function test_a_connection_that_hides_errors_is_refused(): void
    {
        $silent = new PDO('sqlite::memory:', options: [PDO::ATTR_ERRMODE => PDO::ERRMODE_SILENT]);

        $this->expectException(LogicException::class);
        (new PdoChallengeStore($silent))->pull('key');
    }

    public function test_only_known_drivers_have_a_schema(): void
    {
        self::assertCount(2, Schema::statements('mysql'));
        self::assertCount(4, Schema::statements('sqlite', 'my_passkeys', 'my_challenges'));
        $this->expectException(InvalidArgumentException::class);
        Schema::statements('pgsql');
    }
}
