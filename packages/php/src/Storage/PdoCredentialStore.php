<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Storage;

use Closure;
use DateTimeImmutable;
use DateTimeZone;
use Jw1980\Passkey\Base64Url;
use Jw1980\Passkey\Contracts\CredentialStore;
use Jw1980\Passkey\PasskeyException;
use Jw1980\Passkey\StoredPasskey;
use PDO;
use PDOException;
use RuntimeException;

/**
 * Passkeys in a table (see {@see Schema}). Works on MySQL, MariaDB and SQLite. Binary values are
 * stored as base64url text; the primary key is the SHA-256 of the credential ID, because the ID
 * itself can be longer than an index allows.
 */
final class PdoCredentialStore implements CredentialStore
{
    use PdoConnection;

    private const COLUMNS = 'credential_id, user_id, user_handle, public_key, counter, transports, aaguid, backup_eligible, backed_up, attestation_type, name, created_at, last_used_at';

    /** @param PDO|Closure(): PDO $pdo */
    public function __construct(PDO|Closure $pdo, string $table = 'passkeys')
    {
        $this->connect($pdo, $table);
    }

    public function find(string $credentialId): ?StoredPasskey
    {
        $statement = $this->pdo()->prepare('SELECT '.self::COLUMNS." FROM {$this->table} WHERE credential_hash = ?");
        $statement->execute([hash('sha256', $credentialId)]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);

        return is_array($row) ? self::passkey($row) : null;
    }

    public function forUser(string $userId): array
    {
        $statement = $this->pdo()->prepare('SELECT '.self::COLUMNS." FROM {$this->table} WHERE user_id = ? ORDER BY created_at, credential_hash");
        $statement->execute([$userId]);

        return array_values(array_map(self::passkey(...), $statement->fetchAll(PDO::FETCH_ASSOC)));
    }

    public function countForUser(string $userId): int
    {
        $statement = $this->pdo()->prepare("SELECT COUNT(*) FROM {$this->table} WHERE user_id = ?");
        $statement->execute([$userId]);

        return (int) $statement->fetchColumn();
    }

    public function add(StoredPasskey $passkey): void
    {
        $statement = $this->pdo()->prepare(
            "INSERT INTO {$this->table} (credential_hash, ".self::COLUMNS.') VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
        );
        try {
            $statement->execute([
                hash('sha256', $passkey->credentialId),
                Base64Url::encode($passkey->credentialId),
                $passkey->userId,
                Base64Url::encode($passkey->userHandle),
                Base64Url::encode($passkey->publicKey),
                $passkey->counter,
                json_encode($passkey->transports, JSON_THROW_ON_ERROR),
                $passkey->aaguid,
                $passkey->backupEligible ? 1 : 0,
                $passkey->backedUp ? 1 : 0,
                $passkey->attestationType,
                $passkey->name,
                self::text($passkey->createdAt),
                $passkey->lastUsedAt === null ? null : self::text($passkey->lastUsedAt),
            ]);
        } catch (PDOException $failure) {
            // SQLSTATE class 23: integrity constraint violation, here the primary key.
            if (str_starts_with((string) $failure->getCode(), '23')) {
                throw PasskeyException::alreadyRegistered($failure);
            }
            throw $failure;
        }
    }

    public function recordUse(string $credentialId, int $counter, bool $backedUp, DateTimeImmutable $at): void
    {
        $this->pdo()->prepare(
            "UPDATE {$this->table} SET counter = CASE WHEN counter < ? THEN ? ELSE counter END, backed_up = ?, last_used_at = ? WHERE credential_hash = ?"
        )->execute([$counter, $counter, $backedUp ? 1 : 0, self::text($at), hash('sha256', $credentialId)]);
    }

    public function rename(string $userId, string $credentialId, string $name): bool
    {
        // Counted with a SELECT first: MySQL reports zero changed rows when the name stays the same.
        if (! $this->owns($userId, $credentialId)) {
            return false;
        }
        $this->pdo()->prepare("UPDATE {$this->table} SET name = ? WHERE credential_hash = ? AND user_id = ?")
            ->execute([$name, hash('sha256', $credentialId), $userId]);

        return true;
    }

    public function delete(string $userId, string $credentialId): bool
    {
        $statement = $this->pdo()->prepare("DELETE FROM {$this->table} WHERE credential_hash = ? AND user_id = ?");
        $statement->execute([hash('sha256', $credentialId), $userId]);

        return $statement->rowCount() === 1;
    }

    private function owns(string $userId, string $credentialId): bool
    {
        $statement = $this->pdo()->prepare("SELECT 1 FROM {$this->table} WHERE credential_hash = ? AND user_id = ?");
        $statement->execute([hash('sha256', $credentialId), $userId]);

        return $statement->fetchColumn() !== false;
    }

    private static function text(DateTimeImmutable $moment): string
    {
        return $moment->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d H:i:s');
    }

    private static function moment(string $text): DateTimeImmutable
    {
        $moment = DateTimeImmutable::createFromFormat('!Y-m-d H:i:s', $text, new DateTimeZone('UTC'));

        return $moment !== false ? $moment : throw new RuntimeException('A stored passkey has an unreadable date.');
    }

    /** @param array<string, mixed> $row */
    private static function passkey(array $row): StoredPasskey
    {
        $credentialId = Base64Url::decode((string) $row['credential_id']);
        $userHandle = Base64Url::decode((string) $row['user_handle']);
        $publicKey = Base64Url::decode((string) $row['public_key']);
        $transports = json_decode((string) $row['transports'], true);
        if ($credentialId === null || $userHandle === null || $publicKey === null || ! is_array($transports)) {
            throw new RuntimeException('A stored passkey is unreadable.');
        }

        return new StoredPasskey(
            credentialId: $credentialId,
            userId: (string) $row['user_id'],
            userHandle: $userHandle,
            publicKey: $publicKey,
            counter: (int) $row['counter'],
            transports: array_values(array_filter($transports, is_string(...))),
            aaguid: (string) $row['aaguid'],
            backupEligible: (int) $row['backup_eligible'] === 1,
            backedUp: (int) $row['backed_up'] === 1,
            attestationType: (string) $row['attestation_type'],
            name: (string) $row['name'],
            createdAt: self::moment((string) $row['created_at']),
            lastUsedAt: $row['last_used_at'] === null ? null : self::moment((string) $row['last_used_at']),
        );
    }
}
