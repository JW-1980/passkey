<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Laravel;

use Illuminate\Cache\RateLimiter as CacheRateLimiter;
use Jw1980\Passkey\Firebase\Http\RateLimiter;

/** The hub's rate limiter on Laravel's cache. */
final class LaravelRateLimiter implements RateLimiter
{
    public function __construct(private readonly CacheRateLimiter $limiter) {}

    public function attempt(string $key, int $limit, int $windowSeconds): bool
    {
        $key = 'passkey-hub:'.hash('sha256', $key);
        if ($this->limiter->tooManyAttempts($key, $limit)) {
            return false;
        }
        $this->limiter->hit($key, $windowSeconds);

        return true;
    }
}
