<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Tests\Firebase;

use Jw1980\Passkey\Firebase\CurlHttpClient;
use Jw1980\Passkey\Firebase\FirebaseException;
use PHPUnit\Framework\TestCase;

final class CurlHttpClientTest extends TestCase
{
    public function test_an_empty_method_is_a_configuration_error(): void
    {
        if (! function_exists('curl_init')) {
            self::markTestSkipped('ext-curl is not installed.');
        }

        try {
            (new CurlHttpClient)->request('', 'https://example.test/');
            self::fail('an empty method must be refused before curl is called');
        } catch (FirebaseException $failure) {
            self::assertSame(FirebaseException::CONFIGURATION, $failure->errorCode);
        }
    }
}
