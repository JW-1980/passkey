<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Firebase;

/** Rules for a Google Cloud / Firebase project ID. */
final class ProjectId
{
    /** 6 to 30 characters: lowercase letters, digits and hyphens, starting with a letter. */
    public static function isValid(string $projectId): bool
    {
        return preg_match('/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/', $projectId) === 1;
    }

    /**
     * Firebase reserves the prefix `demo-` for projects that exist only in the emulator suite; no
     * real project can have such an ID. Emulator mode is allowed only for these.
     */
    public static function isDemo(string $projectId): bool
    {
        return self::isValid($projectId) && str_starts_with($projectId, 'demo-');
    }
}
