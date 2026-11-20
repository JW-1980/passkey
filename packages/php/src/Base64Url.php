<?php

declare(strict_types=1);

namespace Jw1980\Passkey;

/** Base64url without padding (RFC 4648 §5), the encoding of every binary field in WebAuthn JSON. */
final class Base64Url
{
    public static function encode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    /** Returns null for anything that is not canonical unpadded base64url. */
    public static function decode(string $text): ?string
    {
        if ($text === '' || preg_match('/^[A-Za-z0-9_-]+$/', $text) !== 1 || strlen($text) % 4 === 1) {
            return null;
        }
        $bytes = base64_decode(strtr($text, '-_', '+/'), true);

        return $bytes === false || self::encode($bytes) !== $text ? null : $bytes;
    }
}
