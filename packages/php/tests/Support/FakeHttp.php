<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Tests\Support;

use Closure;
use Jw1980\Passkey\Firebase\HttpClient;
use Jw1980\Passkey\Firebase\HttpResponse;

/** Records requests and answers them with a function of the test. */
final class FakeHttp implements HttpClient
{
    /** @var list<array{method: string, url: string, headers: array<string, string>, body: ?string}> */
    public array $requests = [];

    /** @param Closure(string, string, array<string, string>, ?string): HttpResponse $answer */
    public function __construct(private Closure $answer) {}

    public function request(string $method, string $url, array $headers = [], ?string $body = null): HttpResponse
    {
        $this->requests[] = ['method' => $method, 'url' => $url, 'headers' => $headers, 'body' => $body];

        return ($this->answer)($method, $url, $headers, $body);
    }
}
