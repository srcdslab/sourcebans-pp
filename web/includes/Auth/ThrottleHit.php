<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Auth;

/** One counted attempt, as {@see LoginThrottle::hit()} saw it. */
final class ThrottleHit
{
    public function __construct(
        public readonly int $count,
        public readonly int $limit,
        public readonly int $retryAfter,
    ) {}

    /** Over the limit: refuse without checking the secret. */
    public function blocked(): bool
    {
        return $this->limit > 0 && $this->count > $this->limit;
    }

    /** First refused attempt of the window: the moment to write one audit entry. */
    public function trippedNow(): bool
    {
        return $this->limit > 0 && $this->count === $this->limit + 1;
    }
}
