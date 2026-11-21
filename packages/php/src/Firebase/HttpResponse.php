<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase;

final class HttpResponse
{
    /** @param array<string, string> $headers Lowercase names. */
    public function __construct(
        public readonly int $status,
        public readonly array $headers,
        public readonly string $body,
    ) {}

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }

    /** `max-age` of `Cache-Control`, or null. */
    public function maxAge(): ?int
    {
        $value = $this->header('cache-control');
        if ($value !== null && preg_match('/(?:^|[,\s])max-age=(\d{1,9})/i', $value, $match) === 1) {
            return (int) $match[1];
        }

        return null;
    }
}
