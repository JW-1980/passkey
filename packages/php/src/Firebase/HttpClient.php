<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase;

/**
 * The HTTP the bridge needs (Google's public keys, the Identity Toolkit). An application may pass
 * its own implementation, for example one around its PSR-18 client.
 */
interface HttpClient
{
    /**
     * @param  array<string, string>  $headers
     *
     * @throws FirebaseException with code `unavailable` when no response was received
     */
    public function request(string $method, string $url, array $headers = [], ?string $body = null): HttpResponse;
}
