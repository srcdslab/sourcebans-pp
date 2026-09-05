<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Rest;

/**
 * Shared JSON / query-string coercion for REST handlers.
 */
final class Coerce
{
    public static function bool(mixed $value): bool
    {
        return $value === true || $value === 1 || $value === '1' || $value === 'true';
    }

    /**
     * Ban / comm `length` is minutes on the wire. The row stores seconds.
     */
    public static function minutesFromSeconds(int $seconds): int
    {
        return $seconds <= 0 ? 0 : intdiv($seconds, 60);
    }
}
