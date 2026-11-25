<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Auth;

/**
 * The sign-in counters can't be read or written, most often because the
 * updater hasn't created `:prefix_auth_throttle` yet (#106). Callers
 * refuse the sign-in instead of letting it through uncounted.
 */
final class ThrottleUnavailable extends \RuntimeException {}
