<?php

declare(strict_types=1);

namespace Jw1980\Passkey\Storage;

use Closure;
use InvalidArgumentException;
use LogicException;
use PDO;

/** Shared by the PDO stores: a lazily resolved connection and a checked table name. */
trait PdoConnection
{
    /** @var PDO|Closure(): PDO */
    private PDO|Closure $source;

    private string $table;

    /**
     * @param  PDO|Closure(): PDO  $pdo  A connection, or a function that returns one when it is first
     *                                   needed (a framework's connection manager). It must throw
     *                                   exceptions on errors, the default since PHP 8.
     * @param  string  $table  Letters, digits and underscores only.
     */
    private function connect(PDO|Closure $pdo, string $table): void
    {
        if (preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,63}$/', $table) !== 1) {
            throw new InvalidArgumentException('A table name may hold only letters, digits and underscores.');
        }
        $this->source = $pdo;
        $this->table = $table;
    }

    private function pdo(): PDO
    {
        $pdo = $this->source instanceof PDO ? $this->source : ($this->source)();
        if ($pdo->getAttribute(PDO::ATTR_ERRMODE) !== PDO::ERRMODE_EXCEPTION) {
            throw new LogicException('The PDO connection must use PDO::ERRMODE_EXCEPTION.');
        }

        return $pdo;
    }
}
