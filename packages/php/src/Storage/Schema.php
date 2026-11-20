<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Storage;

use InvalidArgumentException;

/**
 * The two tables of the PDO stores, for applications without a migration tool. Laravel applications
 * use the package migration instead; both describe the same columns.
 */
final class Schema
{
    /**
     * `CREATE TABLE IF NOT EXISTS` statements, safe to run again.
     *
     * @param  'mysql'|'sqlite'  $driver  `mysql` also covers MariaDB.
     * @return list<string>
     */
    public static function statements(string $driver, string $passkeys = 'passkeys', string $challenges = 'passkey_challenges'): array
    {
        foreach ([$passkeys, $challenges] as $table) {
            if (preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,63}$/', $table) !== 1) {
                throw new InvalidArgumentException('A table name may hold only letters, digits and underscores.');
            }
        }
        [$counter, $flag, $suffix] = match ($driver) {
            'mysql' => ['BIGINT UNSIGNED', 'TINYINT(1)', ' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci'],
            'sqlite' => ['INTEGER', 'INTEGER', ''],
            default => throw new InvalidArgumentException("Unsupported driver '{$driver}'."),
        };
        // MySQL has no CREATE INDEX IF NOT EXISTS, so there the index is part of the table.
        $inline = $driver === 'mysql';
        $userIndex = $inline ? ",\n                INDEX {$passkeys}_user_id_index (user_id)" : '';
        $expiryIndex = $inline ? ",\n                INDEX {$challenges}_expires_at_index (expires_at)" : '';

        $statements = [
            "CREATE TABLE IF NOT EXISTS {$passkeys} (
                credential_hash CHAR(64) NOT NULL PRIMARY KEY,
                credential_id TEXT NOT NULL,
                user_id VARCHAR(191) NOT NULL,
                user_handle VARCHAR(86) NOT NULL,
                public_key TEXT NOT NULL,
                counter {$counter} NOT NULL DEFAULT 0,
                transports VARCHAR(255) NOT NULL,
                aaguid CHAR(36) NOT NULL,
                backup_eligible {$flag} NOT NULL DEFAULT 0,
                backed_up {$flag} NOT NULL DEFAULT 0,
                attestation_type VARCHAR(32) NOT NULL,
                name VARCHAR(100) NOT NULL,
                created_at DATETIME NOT NULL,
                last_used_at DATETIME NULL{$userIndex}
            ){$suffix}",
            "CREATE TABLE IF NOT EXISTS {$challenges} (
                key_hash CHAR(64) NOT NULL PRIMARY KEY,
                payload TEXT NOT NULL,
                expires_at BIGINT NOT NULL{$expiryIndex}
            ){$suffix}",
        ];

        if (! $inline) {
            $statements[] = "CREATE INDEX IF NOT EXISTS {$passkeys}_user_id_index ON {$passkeys} (user_id)";
            $statements[] = "CREATE INDEX IF NOT EXISTS {$challenges}_expires_at_index ON {$challenges} (expires_at)";
        }

        return $statements;
    }
}
