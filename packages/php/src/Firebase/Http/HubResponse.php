<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase\Http;

/** A framework-neutral HTTP response of {@see AuthHub}. */
final class HubResponse
{
    /** @param array<string, string> $headers */
    public function __construct(
        public readonly int $status,
        public readonly array $headers,
        public readonly string $body,
    ) {}

    /** @param array<string, string> $headers */
    public static function json(mixed $data, int $status = 200, array $headers = []): self
    {
        return new self($status, ['Content-Type' => 'application/json', 'Cache-Control' => 'no-store'] + $headers,
            $status === 204 ? '' : json_encode($data, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES));
    }

    /** @param array<string, string> $headers */
    public function withHeaders(array $headers): self
    {
        return new self($this->status, $headers + $this->headers, $this->body);
    }

    /** Sends the response through the running PHP SAPI. */
    public function send(): void
    {
        http_response_code($this->status);
        foreach ($this->headers as $name => $value) {
            header($name.': '.$value);
        }
        echo $this->body;
    }
}
