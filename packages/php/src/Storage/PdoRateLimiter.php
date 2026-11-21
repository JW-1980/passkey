<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Storage;

use Closure;
use InvalidArgumentException;
use Jw1980\Passkey\Firebase\Http\RateLimiter;
use PDO;
use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\NativeClock;

/**
 * Fixed-window rate limiter on a PDO table (MySQL, MariaDB, SQLite). Keys are stored hashed, so the
 * table holds no IP addresses. Create the table with {@see statements()}.
 */
final class PdoRateLimiter implements RateLimiter
{
    use PdoConnection;

    private readonly ClockInterface $clock;

    /** @param PDO|Closure(): PDO $pdo */
    public function __construct(PDO|Closure $pdo, string $table = 'passkey_rate_limits', ?ClockInterface $clock = null)
    {
        $this->connect($pdo, $table);
        $this->clock = $clock ?? new NativeClock;
    }

    /**
     * @param  'mysql'|'sqlite'  $driver
     * @return list<string>
     */
    public static function statements(string $driver, string $table = 'passkey_rate_limits'): array
    {
        self::checkName($table);
        $suffix = match ($driver) {
            'mysql' => ' ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci',
            'sqlite' => '',
            default => throw new InvalidArgumentException("Unsupported driver '{$driver}'."),
        };

        return ["CREATE TABLE IF NOT EXISTS {$table} (
            key_hash CHAR(64) NOT NULL,
            window_start BIGINT NOT NULL,
            hits INTEGER NOT NULL,
            PRIMARY KEY (key_hash, window_start)
        ){$suffix}"];
    }

    public function attempt(string $key, int $limit, int $windowSeconds): bool
    {
        if ($limit < 1 || $windowSeconds < 1) {
            return false;
        }
        $now = $this->clock->now()->getTimestamp();
        $window = intdiv($now, $windowSeconds) * $windowSeconds;
        $hash = hash('sha256', $key);
        $pdo = $this->pdo();

        $update = $pdo->prepare("UPDATE {$this->table} SET hits = hits + 1 WHERE key_hash = ? AND window_start = ? AND hits < ?");
        $update->execute([$hash, $window, $limit]);
        if ($update->rowCount() === 1) {
            return true;
        }
        try {
            $pdo->prepare("INSERT INTO {$this->table} (key_hash, window_start, hits) VALUES (?, ?, 1)")->execute([$hash, $window]);
        } catch (\PDOException $failure) {
            // SQLSTATE 23000: the row exists, so the limit is reached (or another request just
            // created it). Anything else is a real database fault and is not hidden as a 429.
            if ($failure->getCode() !== '23000') {
                throw $failure;
            }

            return false;
        }
        // Old windows are useless; remove some of them now and then.
        if (random_int(1, 50) === 1) {
            $pdo->prepare("DELETE FROM {$this->table} WHERE window_start < ?")->execute([$window - 3600]);
        }

        return true;
    }

    private static function checkName(string $table): void
    {
        if (preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,63}$/', $table) !== 1) {
            throw new InvalidArgumentException('A table name may hold only letters, digits and underscores.');
        }
    }
}
