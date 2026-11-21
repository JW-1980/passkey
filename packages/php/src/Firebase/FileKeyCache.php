<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase;

/**
 * Keeps the keys in one JSON file, so that every PHP-FPM request does not fetch them again. The
 * file holds only Google's public certificates. Writes are atomic (temporary file and rename).
 */
final class FileKeyCache implements KeyCache
{
    public function __construct(private readonly string $path) {}

    public function get(): ?array
    {
        if (! is_file($this->path)) {
            return null;
        }
        $data = json_decode((string) @file_get_contents($this->path), true);
        if (! is_array($data) || ! is_int($data['expiresAt'] ?? null) || ! is_array($data['keys'] ?? null)) {
            return null;
        }
        $keys = [];
        foreach ($data['keys'] as $kid => $pem) {
            if (is_string($kid) && is_string($pem)) {
                $keys[$kid] = $pem;
            }
        }

        return ['keys' => $keys, 'expiresAt' => $data['expiresAt']];
    }

    public function put(array $keys, int $expiresAt): void
    {
        $temporary = $this->path.'.'.bin2hex(random_bytes(6)).'.tmp';
        if (@file_put_contents($temporary, json_encode(['keys' => $keys, 'expiresAt' => $expiresAt], JSON_THROW_ON_ERROR)) !== false) {
            @rename($temporary, $this->path);
        }
        @unlink($temporary);
    }
}
