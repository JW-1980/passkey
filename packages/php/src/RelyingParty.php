<?php

declare(strict_types=1);

namespace Jw1980\Passkey;

use InvalidArgumentException;

/**
 * Who the passkeys belong to: the relying-party ID (a domain), the name people see in the passkey
 * prompt, and the exact origins that may use the passkeys.
 *
 * An origin is one of:
 * - `https://host[:port]` where host is the relying-party ID or one of its subdomains;
 * - `http://localhost[:port]`, only when the relying-party ID is `localhost` (development);
 * - `android:apk-key-hash:<hash>` for a native Android app (see {@see WellKnown::androidOrigin()}).
 *
 * Native iOS apps send the `https://` origin of their associated domain and need no entry.
 *
 * **Related origins** (WebAuthn Level 3, "Related Origin Requests") are `https://` origins on
 * *other* domains that may use the same passkeys, for example the sites of other products that sign
 * in through one central relying party. The browser allows that only when
 * `https://<id>/.well-known/webauthn` lists them; serve {@see WellKnown::relatedOrigins()} there.
 */
final class RelyingParty
{
    /** @var list<string> */
    public readonly array $origins;

    /** @var list<string> */
    public readonly array $relatedOrigins;

    /**
     * @param  list<string>  $origins
     * @param  list<string>  $relatedOrigins  `https://host[:port]` on other domains.
     */
    public function __construct(
        public readonly string $id,
        public readonly string $name,
        array $origins,
        array $relatedOrigins = [],
    ) {
        if (! self::isDomain($id)) {
            throw new InvalidArgumentException('The relying-party ID must be a lowercase domain name, not an address or a URL.');
        }
        if (trim($name) === '') {
            throw new InvalidArgumentException('The relying party needs a name.');
        }
        if ($origins === []) {
            throw new InvalidArgumentException('The relying party needs at least one allowed origin.');
        }
        $normalized = [];
        foreach ($origins as $origin) {
            $normalized[] = $this->normalize($origin);
        }
        $this->origins = array_values(array_unique($normalized));
        $related = [];
        foreach ($relatedOrigins as $origin) {
            $related[] = self::normalizeRelated($origin);
        }
        $this->relatedOrigins = array_values(array_diff(array_unique($related), $this->origins));
    }

    /**
     * Every origin whose WebAuthn responses are accepted.
     *
     * @return list<string>
     */
    public function allowedOrigins(): array
    {
        return array_values(array_merge($this->origins, $this->relatedOrigins));
    }

    private static function normalizeRelated(string $origin): string
    {
        $parts = parse_url(trim($origin));
        $host = is_array($parts) ? strtolower($parts['host'] ?? '') : '';
        if (! is_array($parts) || strtolower($parts['scheme'] ?? '') !== 'https' || ! self::isDomain($host)
            || ($parts['path'] ?? '') !== '' && ($parts['path'] ?? '') !== '/'
            || isset($parts['query']) || isset($parts['fragment']) || isset($parts['user']) || isset($parts['pass'])) {
            throw new InvalidArgumentException("The related origin '{$origin}' must be https://host[:port] without a path.");
        }
        $port = isset($parts['port']) && $parts['port'] !== 443 ? ':'.$parts['port'] : '';

        return 'https://'.$host.$port;
    }

    /** A relying party whose ID is the host of the application URL and whose only origin is that URL. */
    public static function forUrl(string $applicationUrl, string $name): self
    {
        $host = parse_url(trim($applicationUrl), PHP_URL_HOST);
        if (! is_string($host) || $host === '') {
            throw new InvalidArgumentException('The application URL has no host.');
        }

        return new self(strtolower($host), $name, [$applicationUrl]);
    }

    private static function isDomain(string $host): bool
    {
        if ($host === 'localhost') {
            return true;
        }

        return $host === strtolower($host)
            && filter_var($host, FILTER_VALIDATE_IP) === false
            && filter_var($host, FILTER_VALIDATE_DOMAIN, FILTER_FLAG_HOSTNAME) !== false
            && str_contains($host, '.');
    }

    private function normalize(string $origin): string
    {
        $origin = trim($origin);
        if (str_starts_with($origin, 'android:apk-key-hash:')) {
            $hash = Base64Url::decode(substr($origin, strlen('android:apk-key-hash:')));
            if ($hash === null || strlen($hash) !== 32) {
                throw new InvalidArgumentException('An Android origin must end in the base64url SHA-256 hash of the signing certificate.');
            }

            return $origin;
        }

        $parts = parse_url($origin);
        $scheme = is_array($parts) ? strtolower($parts['scheme'] ?? '') : '';
        $host = is_array($parts) ? strtolower($parts['host'] ?? '') : '';
        $path = is_array($parts) ? ($parts['path'] ?? '') : '';
        if (! is_array($parts) || $host === '' || ($path !== '' && $path !== '/')
            || isset($parts['query']) || isset($parts['fragment']) || isset($parts['user']) || isset($parts['pass'])) {
            throw new InvalidArgumentException("The origin '{$origin}' must be scheme://host[:port] without a path.");
        }
        $belongs = $host === $this->id || str_ends_with($host, '.'.$this->id);
        if (! $belongs) {
            throw new InvalidArgumentException("The origin '{$origin}' does not belong to the relying party '{$this->id}'.");
        }
        $secure = $scheme === 'https' || ($scheme === 'http' && $host === 'localhost' && $this->id === 'localhost');
        if (! $secure) {
            throw new InvalidArgumentException("The origin '{$origin}' must use https (http is only allowed for localhost).");
        }
        $defaultPort = $scheme === 'https' ? 443 : 80;
        $port = isset($parts['port']) && $parts['port'] !== $defaultPort ? ':'.$parts['port'] : '';

        return $scheme.'://'.$host.$port;
    }
}
