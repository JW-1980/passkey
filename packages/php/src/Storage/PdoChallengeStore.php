<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Storage;

use Closure;
use Jw1980\Passkey\Contracts\ChallengeStore;
use PDO;
use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\NativeClock;

/**
 * Challenges and handoff codes in a table (see {@see Schema}). Works on MySQL, MariaDB and SQLite.
 * Single use rests on the `DELETE`: of two requests with the same key only one deletes the row.
 */
final class PdoChallengeStore implements ChallengeStore
{
    use PdoConnection;

    private readonly ClockInterface $clock;

    /** @param PDO|Closure(): PDO $pdo */
    public function __construct(PDO|Closure $pdo, string $table = 'passkey_challenges', ?ClockInterface $clock = null)
    {
        $this->connect($pdo, $table);
        $this->clock = $clock ?? new NativeClock;
    }

    public function put(string $key, string $payload, int $ttlSeconds): void
    {
        $now = $this->clock->now()->getTimestamp();
        $pdo = $this->pdo();
        // Expired rows are cleared as new ones arrive, so the table stays small without a scheduled job.
        $pdo->prepare("DELETE FROM {$this->table} WHERE expires_at <= ?")->execute([$now]);
        $pdo->prepare("INSERT INTO {$this->table} (key_hash, payload, expires_at) VALUES (?, ?, ?)")
            ->execute([hash('sha256', $key), $payload, $now + $ttlSeconds]);
    }

    public function pull(string $key): ?string
    {
        $hash = hash('sha256', $key);
        $pdo = $this->pdo();
        $select = $pdo->prepare("SELECT payload, expires_at FROM {$this->table} WHERE key_hash = ?");
        $select->execute([$hash]);
        $row = $select->fetch(PDO::FETCH_ASSOC);
        if (! is_array($row)) {
            return null;
        }
        $delete = $pdo->prepare("DELETE FROM {$this->table} WHERE key_hash = ?");
        $delete->execute([$hash]);
        if ($delete->rowCount() !== 1 || (int) $row['expires_at'] <= $this->clock->now()->getTimestamp()) {
            return null;
        }

        return (string) $row['payload'];
    }
}
