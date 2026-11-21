<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase;

/**
 * Keeps the keys in one JSON file shared by all PHP-FPM workers. Writes are atomic (temporary file
 * and rename).
 *
 * The file is a trust anchor (see {@see KeyCache}): put it in a directory only the application's
 * user can write. A file owned by another user, or writable by group or others, is ignored.
 */
final class FileKeyCache implements KeyCache
{
    private const MAX_AGE = 86400;

    public function __construct(private readonly string $path) {}

    public function get(): ?array
    {
        if (! is_file($this->path) || ! $this->trusted()) {
            return null;
        }
        $data = json_decode((string) @file_get_contents($this->path), true);
        if (! is_array($data) || ! is_int($data['expiresAt'] ?? null) || ! is_int($data['fetchedAt'] ?? null) || ! is_array($data['keys'] ?? null)) {
            return null;
        }
        $keys = [];
        foreach ($data['keys'] as $kid => $pem) {
            if (is_string($kid) && is_string($pem)) {
                $keys[$kid] = $pem;
            }
        }

        // Never longer than a day after the fetch, whatever the file says.
        return ['keys' => $keys, 'expiresAt' => min($data['expiresAt'], $data['fetchedAt'] + self::MAX_AGE), 'fetchedAt' => $data['fetchedAt']];
    }

    public function put(array $keys, int $expiresAt, int $fetchedAt): void
    {
        $temporary = $this->path.'.'.bin2hex(random_bytes(6)).'.tmp';
        $json = json_encode(['keys' => $keys, 'expiresAt' => $expiresAt, 'fetchedAt' => $fetchedAt], JSON_THROW_ON_ERROR);
        if (@file_put_contents($temporary, $json) !== false) {
            @chmod($temporary, 0600);
            if (! @rename($temporary, $this->path)) {
                error_log('passkey: the Firebase key cache could not be written: '.$this->path);
            }
        }
        @unlink($temporary);
    }

    private function trusted(): bool
    {
        clearstatcache(true, $this->path);
        $mode = @fileperms($this->path);
        if ($mode === false || ($mode & 0o022) !== 0) {
            return false;
        }
        if (function_exists('posix_geteuid')) {
            return @fileowner($this->path) === posix_geteuid();
        }

        return true;
    }
}
