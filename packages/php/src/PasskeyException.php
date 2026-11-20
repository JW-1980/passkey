<?php

declare(strict_types=1);

namespace Jw1980\Passkey;

use RuntimeException;
use Throwable;

/**
 * A refusal the client may see. `errorCode` is stable and meant for programs; the message is meant
 * for people and never holds internals. The underlying cause stays in `getPrevious()` for the
 * server's own log.
 */
final class PasskeyException extends RuntimeException
{
    public const CEREMONY_EXPIRED = 'ceremony_expired';

    public const INVALID_REQUEST = 'invalid_request';

    public const INVALID_REGISTRATION = 'invalid_registration';

    public const INVALID_PASSKEY = 'invalid_passkey';

    public const ALREADY_REGISTERED = 'already_registered';

    public const TOO_MANY_PASSKEYS = 'too_many_passkeys';

    public const NOT_FOUND = 'not_found';

    public const INVALID_HANDOFF = 'invalid_handoff';

    private function __construct(
        public readonly string $errorCode,
        public readonly int $httpStatus,
        string $message,
        ?Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    public static function ceremonyExpired(): self
    {
        return new self(self::CEREMONY_EXPIRED, 400, 'This passkey request has expired. Please try again.');
    }

    public static function invalidRequest(string $message): self
    {
        return new self(self::INVALID_REQUEST, 422, $message);
    }

    public static function invalidRegistration(?Throwable $previous = null): self
    {
        return new self(self::INVALID_REGISTRATION, 400, 'This passkey could not be registered.', $previous);
    }

    /** One message for every reason a sign-in fails, so a caller learns nothing about accounts. */
    public static function invalidPasskey(?Throwable $previous = null): self
    {
        return new self(self::INVALID_PASSKEY, 401, 'This passkey is not valid.', $previous);
    }

    public static function alreadyRegistered(?Throwable $previous = null): self
    {
        return new self(self::ALREADY_REGISTERED, 409, 'This passkey is already registered.', $previous);
    }

    public static function tooManyPasskeys(int $maximum): self
    {
        return new self(self::TOO_MANY_PASSKEYS, 409, "An account can hold at most {$maximum} passkeys.");
    }

    public static function notFound(): self
    {
        return new self(self::NOT_FOUND, 404, 'This passkey does not exist.');
    }

    public static function invalidHandoff(): self
    {
        return new self(self::INVALID_HANDOFF, 400, 'This sign-in handoff is not valid or has expired.');
    }

    /** @return array{error: array{code: string, message: string}} */
    public function toArray(): array
    {
        return ['error' => ['code' => $this->errorCode, 'message' => $this->getMessage()]];
    }
}
