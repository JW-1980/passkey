<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase\Http;

/** A framework-neutral HTTP request for {@see AuthHub}. */
final class HubRequest
{
    /** @var array<string, string> */
    public readonly array $headers;

    /** The path without the query string. */
    public readonly string $path;

    /**
     * @param  string  $path  A path, with or without a query string (the query is dropped: the hub
     *                        reads nothing from it).
     * @param  array<string, string>  $headers  Any case; stored lowercase.
     */
    public function __construct(
        public readonly string $method,
        string $path,
        array $headers,
        public readonly string $body,
        public readonly string $clientIp,
    ) {
        $this->path = (string) parse_url($path, PHP_URL_PATH);
        $lower = [];
        foreach ($headers as $name => $value) {
            $lower[strtolower($name)] = $value;
        }
        $this->headers = $lower;
    }

    /** The request of the running PHP SAPI (php-fpm, Apache, the built-in server). */
    public static function fromGlobals(): self
    {
        $headers = [];
        foreach ($_SERVER as $name => $value) {
            if (is_string($value) && str_starts_with($name, 'HTTP_')) {
                $headers[str_replace('_', '-', substr($name, 5))] = $value;
            }
        }
        if (isset($_SERVER['CONTENT_TYPE']) && is_string($_SERVER['CONTENT_TYPE'])) {
            $headers['content-type'] = $_SERVER['CONTENT_TYPE'];
        }
        $method = is_string($_SERVER['REQUEST_METHOD'] ?? null) ? $_SERVER['REQUEST_METHOD'] : 'GET';
        $uri = is_string($_SERVER['REQUEST_URI'] ?? null) ? $_SERVER['REQUEST_URI'] : '/';

        return new self(
            strtoupper($method),
            (string) parse_url($uri, PHP_URL_PATH),
            $headers,
            (string) file_get_contents('php://input'),
            is_string($_SERVER['REMOTE_ADDR'] ?? null) ? $_SERVER['REMOTE_ADDR'] : '',
        );
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }
}
