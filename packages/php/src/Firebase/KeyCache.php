<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase;

/** Where Google's public keys are kept between requests. */
interface KeyCache
{
    /** @return array{keys: array<string, string>, expiresAt: int}|null */
    public function get(): ?array;

    /** @param array<string, string> $keys kid → PEM */
    public function put(array $keys, int $expiresAt): void;
}
