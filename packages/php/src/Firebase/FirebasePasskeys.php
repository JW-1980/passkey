<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase;

use InvalidArgumentException;
use Jw1980\Passkey\Ceremony;
use Jw1980\Passkey\Handoff\HandoffServer;
use Jw1980\Passkey\PasskeyException;
use Jw1980\Passkey\PasskeyServer;
use Jw1980\Passkey\PasskeyUser;
use Jw1980\Passkey\StoredPasskey;

/**
 * Passkeys for Firebase users: the auth hub's logic, without HTTP.
 *
 * - A signed-in Firebase user (proved by an ID token) registers and manages passkeys; the passkey
 *   store keys them by Firebase uid.
 * - A passkey sign-in answers a Firebase custom token for that uid, with `login_method: passkey`.
 * - The desktop handoff is authorized by a Firebase ID token and answers a custom token with
 *   `login_method: handoff` and how the browser signed in.
 *
 * Registering or deleting a passkey and authorizing a handoff need a recent sign-in (`auth_time`),
 * so that a stolen or forgotten session cannot add a permanent way in.
 */
final class FirebasePasskeys
{
    public function __construct(
        private readonly PasskeyServer $passkeys,
        private readonly HandoffServer $handoff,
        private readonly CustomTokenIssuer $tokens,
        private readonly IdTokenVerifier $verifier,
        private readonly ?AdminClient $admin = null,
        private readonly int $recentSignInSeconds = 600,
    ) {
        if ($recentSignInSeconds < 60 || $recentSignInSeconds > 3600) {
            throw new InvalidArgumentException('The recent sign-in window must be 60 to 3600 seconds.');
        }
        if ($tokens->projectId() !== $verifier->projectId()) {
            throw new InvalidArgumentException('The service account and the token verifier belong to different Firebase projects.');
        }
    }

    /**
     * The signed-in Firebase user of an `Authorization` header value (`Bearer <ID token>`).
     *
     * @throws FirebaseException
     */
    public function identify(?string $authorization): FirebaseIdentity
    {
        if ($authorization === null || preg_match('/^Bearer ([A-Za-z0-9._-]+)$/', trim($authorization), $match) !== 1) {
            throw FirebaseException::invalidToken('no bearer token');
        }

        return $this->verifier->verify($match[1]);
    }

    public function beginRegistration(FirebaseIdentity $identity): Ceremony
    {
        $this->requireRecent($identity);

        return $this->passkeys->beginRegistration(self::user($identity));
    }

    /** @param array<array-key, mixed> $credential */
    public function finishRegistration(FirebaseIdentity $identity, string $ceremonyId, array $credential, ?string $name = null): StoredPasskey
    {
        $this->requireRecent($identity);

        return $this->passkeys->finishRegistration($ceremonyId, $credential, self::user($identity), $name);
    }

    public function beginSignIn(): Ceremony
    {
        return $this->passkeys->beginAuthentication();
    }

    /**
     * Verifies a passkey sign-in and mints the custom token. With an admin client, a uid that no
     * longer exists in Firebase is refused and its passkeys are removed: otherwise Firebase would
     * create a new, empty user for the old uid.
     *
     * @param  array<array-key, mixed>  $credential
     */
    public function finishSignIn(string $ceremonyId, array $credential): CustomTokenGrant
    {
        $result = $this->passkeys->finishAuthentication($ceremonyId, $credential);
        if ($this->admin !== null) {
            $user = $this->admin->lookup($result->userId);
            if ($user === null) {
                $this->deleteUser($result->userId);
                throw PasskeyException::invalidPasskey();
            }
            if ($user['disabled']) {
                throw PasskeyException::invalidPasskey();
            }
        }

        return $this->grant($result->userId, ['login_method' => 'passkey', 'login_mfa' => true]);
    }

    /** @return list<StoredPasskey> */
    public function passkeys(FirebaseIdentity $identity): array
    {
        return $this->passkeys->passkeys($identity->uid);
    }

    public function rename(FirebaseIdentity $identity, string $id, string $name): StoredPasskey
    {
        return $this->passkeys->rename($identity->uid, $id, $name);
    }

    public function delete(FirebaseIdentity $identity, string $id): void
    {
        $this->requireRecent($identity);
        $this->passkeys->delete($identity->uid, $id);
    }

    /** Browser side of the desktop handoff; returns the loopback address. */
    public function authorizeHandoff(FirebaseIdentity $identity, string $challenge, int $port, string $state): string
    {
        $this->requireRecent($identity);

        return $this->handoff->authorize($identity->uid, $challenge, $port, $state, [
            'via' => $identity->method(),
            'mfa' => $identity->isMultiFactor(),
            'authTime' => $identity->effectiveAuthTime(),
        ]);
    }

    public function exchangeHandoff(string $code, string $codeVerifier): CustomTokenGrant
    {
        $grant = $this->handoff->exchange($code, $codeVerifier);
        $via = is_string($grant->context['via'] ?? null) ? substr($grant->context['via'], 0, 64) : 'unknown';

        return $this->grant($grant->userId, [
            'login_method' => 'handoff',
            'login_via' => $via,
            'login_mfa' => ($grant->context['mfa'] ?? false) === true,
            // The browser sign-in time travels along, so recency checks keep using it (SR-6).
            'login_auth_time' => is_int($grant->context['authTime'] ?? null) ? $grant->context['authTime'] : 0,
        ]);
    }

    /** Removes every passkey of a Firebase user; call it when the user is deleted. Returns the count. */
    public function deleteUser(string $uid): int
    {
        $count = 0;
        foreach ($this->passkeys->passkeys($uid) as $passkey) {
            try {
                $this->passkeys->delete($uid, $passkey->id());
                $count++;
            } catch (PasskeyException) {
                // Removed concurrently: the goal is reached either way.
            }
        }

        return $count;
    }

    /** @param array<string, scalar> $claims */
    private function grant(string $uid, array $claims): CustomTokenGrant
    {
        return new CustomTokenGrant($uid, $this->tokens->issue($uid, $claims), $this->tokens->ttlSeconds());
    }

    private function requireRecent(FirebaseIdentity $identity): void
    {
        if (! $identity->isRecent($this->recentSignInSeconds)) {
            throw FirebaseException::reauthenticationRequired();
        }
    }

    private static function user(FirebaseIdentity $identity): PasskeyUser
    {
        $label = $identity->label();

        return new PasskeyUser($identity->uid, $label, $identity->name ?? $label);
    }
}
