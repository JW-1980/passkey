<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase;

/**
 * Default {@see HttpClient} on ext-curl. curl honours the `HTTPS_PROXY` and `NO_PROXY` variables and
 * verifies TLS certificates (never switched off here).
 */
final class CurlHttpClient implements HttpClient
{
    public function __construct(private readonly int $timeoutSeconds = 10) {}

    public function request(string $method, string $url, array $headers = [], ?string $body = null): HttpResponse
    {
        if (! function_exists('curl_init')) {
            throw FirebaseException::configuration('ext-curl is needed for the default HTTP client.');
        }
        $handle = curl_init($url);
        if ($handle === false) {
            throw FirebaseException::unavailable('HTTP');
        }
        $received = [];
        $lines = [];
        foreach ($headers as $name => $value) {
            $lines[] = $name.': '.$value;
        }
        curl_setopt_array($handle, [
            CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => $this->timeoutSeconds,
            CURLOPT_TIMEOUT => $this->timeoutSeconds,
            CURLOPT_HTTPHEADER => $lines,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS | CURLPROTO_HTTP,
            CURLOPT_HEADERFUNCTION => static function ($curl, string $line) use (&$received): int {
                $parts = explode(':', $line, 2);
                if (count($parts) === 2) {
                    $received[strtolower(trim($parts[0]))] = trim($parts[1]);
                }

                return strlen($line);
            },
        ]);
        if ($body !== null) {
            curl_setopt($handle, CURLOPT_POSTFIELDS, $body);
        }
        $result = curl_exec($handle);
        $status = (int) curl_getinfo($handle, CURLINFO_RESPONSE_CODE);
        $error = curl_error($handle);
        curl_close($handle);
        if (! is_string($result) || $status === 0) {
            throw FirebaseException::unavailable(parse_url($url, PHP_URL_HOST) ?: 'HTTP', $error !== '' ? new \RuntimeException($error) : null);
        }

        /** @var array<string, string> $received */
        return new HttpResponse($status, $received, $result);
    }
}
