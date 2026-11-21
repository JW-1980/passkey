<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase\Http;

interface RateLimiter
{
    /** Counts one attempt; false when the key used up its limit in the current window. */
    public function attempt(string $key, int $limit, int $windowSeconds): bool;
}
