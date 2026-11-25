<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Auth;

/**
 * The sign-in counters can't be read or written (#106). Callers refuse
 * the sign-in instead of letting it through uncounted.
 *
 * `$tableMissing` is true when `:prefix_auth_throttle` doesn't exist yet,
 * the usual cause and the only one running the updater fixes. Any other
 * error (a deadlock, a lock wait timeout, a lost connection) must not tell
 * people to run the updater.
 */
final class ThrottleUnavailable extends \RuntimeException
{
    public function __construct(
        string $message,
        public readonly bool $tableMissing = false,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    /** Wrap a PDO error; SQLSTATE 42S02 (ER_NO_SUCH_TABLE) is the missing table. */
    public static function fromPdo(string $what, \PDOException $e): self
    {
        $sqlState = is_array($e->errorInfo) ? (string) ($e->errorInfo[0] ?? '') : '';
        if ($sqlState === '') {
            $sqlState = (string) $e->getCode();
        }
        return new self($what . ': ' . $e->getMessage(), $sqlState === '42S02', $e);
    }
}
