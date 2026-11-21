<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase;

use RuntimeException;
use Throwable;

/**
 * A refusal or failure of the Firebase bridge. `errorCode` is stable and meant for programs; the
 * message is meant for people and never holds a token or key. The cause stays in `getPrevious()`.
 */
final class FirebaseException extends RuntimeException
{
    /** The ID token is missing, malformed, expired, for another project or not signed by Google. */
    public const INVALID_TOKEN = 'unauthenticated';

    /** The token is valid, but the sign-in is older than the action allows. */
    public const REAUTHENTICATION_REQUIRED = 'reauthentication_required';

    /** Google's keys or the Identity Toolkit could not be reached; nothing was decided. */
    public const UNAVAILABLE = 'unavailable';

    /** The bridge is set up wrongly (key file, project ID). Never caused by a client. */
    public const CONFIGURATION = 'configuration';

    /** The Identity Toolkit refused an admin request. */
    public const ADMIN_REFUSED = 'admin_refused';

    private function __construct(
        public readonly string $errorCode,
        public readonly int $httpStatus,
        string $message,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    /** One message for every reason a token is refused, so a caller learns nothing more. */
    public static function invalidToken(string $reason = '', ?Throwable $previous = null): self
    {
        $exception = new self(self::INVALID_TOKEN, 401, 'Please sign in again.', $previous);
        $exception->reason = $reason;

        return $exception;
    }

    public static function reauthenticationRequired(): self
    {
        return new self(self::REAUTHENTICATION_REQUIRED, 403, 'Please confirm it is you by signing in again.');
    }

    public static function unavailable(string $what, ?Throwable $previous = null): self
    {
        return new self(self::UNAVAILABLE, 503, "The sign-in service is not reachable ({$what}). Please try again.", $previous);
    }

    public static function configuration(string $message, ?Throwable $previous = null): self
    {
        return new self(self::CONFIGURATION, 500, $message, $previous);
    }

    public static function adminRefused(string $firebaseCode): self
    {
        return new self(self::ADMIN_REFUSED, 502, "Firebase refused the request ({$firebaseCode}).");
    }

    /**
     * Why a token was refused, for the server's own log only (never sent to the client).
     */
    public string $reason = '';

    /**
     * What a client may see. A configuration error never shows its detail (environment variable
     * names, project IDs): that stays in `getMessage()` for the server's log.
     *
     * @return array{error: array{code: string, message: string}}
     */
    public function toArray(): array
    {
        $message = $this->errorCode === self::CONFIGURATION ? 'The sign-in service is not available.' : $this->getMessage();

        return ['error' => ['code' => $this->errorCode, 'message' => $message]];
    }
}
