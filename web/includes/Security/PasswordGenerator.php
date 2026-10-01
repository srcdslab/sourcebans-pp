<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Security;

use Sbpp\Config;

/**
 * Configurable random password generator.
 *
 * Single source for every "Generate password" affordance in the panel
 * (Add admin, Edit admin, Your account, Add / Edit server RCON) via the
 * `admins.generate_password` JSON action, and for the REST
 * `POST /admins` fallback when no password is supplied.
 *
 * Defaults live in `:prefix_settings` under `config.password.generator.*`
 * (owner-editable in Settings > Main). Callers may override any option
 * per request; overrides are clamped to the same bounds as the defaults.
 *
 * Randomness is `random_int()` (CSPRNG). The output always contains at
 * least one character from every enabled set, then the result is
 * Fisher-Yates shuffled so the guaranteed characters don't sit at fixed
 * positions.
 */
final class PasswordGenerator
{
    public const LOWERCASE = 'abcdefghijklmnopqrstuvwxyz';
    public const UPPERCASE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    public const DIGITS    = '0123456789';
    /**
     * Deliberately excludes quotes, backslash, semicolon, space, and
     * backtick: generated passwords end up in SourceMod configs,
     * `server.cfg` (`rcon_password`), and the game console, where those
     * characters split commands or break quoting.
     */
    public const SYMBOLS   = '!#$%&*+-.:=?@^_~';
    /** Characters that are easy to misread (`0`/`O`, `1`/`l`/`I`). */
    public const AMBIGUOUS = '0O1lI';

    /** Absolute floor, applied even when the panel minimum is lower. */
    public const MIN_LENGTH = 8;
    public const MAX_LENGTH = 128;
    public const DEFAULT_LENGTH = 20;

    public const SETTING_LENGTH            = 'config.password.generator.length';
    public const SETTING_LOWERCASE         = 'config.password.generator.lowercase';
    public const SETTING_UPPERCASE         = 'config.password.generator.uppercase';
    public const SETTING_DIGITS            = 'config.password.generator.digits';
    public const SETTING_SYMBOLS           = 'config.password.generator.symbols';
    public const SETTING_EXCLUDE_AMBIGUOUS = 'config.password.generator.exclude_ambiguous';

    /** Option key => settings key. Order is the wire order. */
    public const SETTINGS = [
        'length'            => self::SETTING_LENGTH,
        'lowercase'         => self::SETTING_LOWERCASE,
        'uppercase'         => self::SETTING_UPPERCASE,
        'digits'            => self::SETTING_DIGITS,
        'symbols'           => self::SETTING_SYMBOLS,
        'exclude_ambiguous' => self::SETTING_EXCLUDE_AMBIGUOUS,
    ];

    /** Character-set option keys, in the order they're guaranteed. */
    private const SETS = ['lowercase', 'uppercase', 'digits', 'symbols'];

    /**
     * Smallest length the generator will produce: the larger of the
     * absolute floor and the panel's `config.password.minlength`, so a
     * generated password always passes the panel's own validation.
     */
    public static function minLength(): int
    {
        $panelMin = defined('MIN_PASS_LENGTH') ? (int) MIN_PASS_LENGTH : 0;
        return min(self::MAX_LENGTH, max(self::MIN_LENGTH, $panelMin));
    }

    /**
     * Owner-configured defaults from `:prefix_settings`. Missing rows
     * (an install that hasn't run the updater yet) fall back to the
     * shipped defaults. Never throws: a misconfigured row that disables
     * every character set falls back to letters + digits.
     *
     * @return array{length: int, lowercase: bool, uppercase: bool, digits: bool, symbols: bool, exclude_ambiguous: bool}
     */
    public static function defaults(): array
    {
        $raw = [
            'length'            => self::readSetting(self::SETTING_LENGTH, (string) self::DEFAULT_LENGTH),
            'lowercase'         => self::readSetting(self::SETTING_LOWERCASE, '1'),
            'uppercase'         => self::readSetting(self::SETTING_UPPERCASE, '1'),
            'digits'            => self::readSetting(self::SETTING_DIGITS, '1'),
            'symbols'           => self::readSetting(self::SETTING_SYMBOLS, '1'),
            'exclude_ambiguous' => self::readSetting(self::SETTING_EXCLUDE_AMBIGUOUS, '1'),
        ];

        $opts = self::normalize($raw, self::builtinDefaults());
        if (!self::hasAnySet($opts)) {
            $opts['lowercase'] = true;
            $opts['uppercase'] = true;
            $opts['digits']    = true;
        }
        return $opts;
    }

    /**
     * Merge per-request overrides on top of `$defaults` (or the
     * configured defaults) and clamp the length.
     *
     * @param array<string, mixed> $overrides
     * @param array{length: int, lowercase: bool, uppercase: bool, digits: bool, symbols: bool, exclude_ambiguous: bool}|null $defaults
     * @return array{length: int, lowercase: bool, uppercase: bool, digits: bool, symbols: bool, exclude_ambiguous: bool}
     * @throws \InvalidArgumentException when no character set is enabled
     */
    public static function resolve(array $overrides, ?array $defaults = null): array
    {
        $opts = self::normalize($overrides, $defaults ?? self::defaults());
        if (!self::hasAnySet($opts)) {
            throw new \InvalidArgumentException('Pick at least one character set.');
        }
        return $opts;
    }

    /**
     * @param array{length: int, lowercase: bool, uppercase: bool, digits: bool, symbols: bool, exclude_ambiguous: bool}|null $options
     * @throws \InvalidArgumentException when no character set is enabled
     */
    public static function generate(?array $options = null): string
    {
        $opts = $options === null ? self::defaults() : self::resolve($options, self::builtinDefaults());

        $pools = [];
        foreach (self::SETS as $set) {
            if ($opts[$set]) {
                $pools[] = self::pool($set, $opts['exclude_ambiguous']);
            }
        }
        if ($pools === []) {
            throw new \InvalidArgumentException('Pick at least one character set.');
        }

        $length = max($opts['length'], count($pools));
        $all = implode('', $pools);

        $chars = [];
        foreach ($pools as $pool) {
            $chars[] = self::pick($pool);
        }
        while (count($chars) < $length) {
            $chars[] = self::pick($all);
        }

        for ($i = count($chars) - 1; $i > 0; $i--) {
            $j = random_int(0, $i);
            [$chars[$i], $chars[$j]] = [$chars[$j], $chars[$i]];
        }

        return implode('', $chars);
    }

    /**
     * Characters a given set contributes, minus the ambiguous ones when
     * requested.
     */
    public static function pool(string $set, bool $excludeAmbiguous): string
    {
        $chars = match ($set) {
            'lowercase' => self::LOWERCASE,
            'uppercase' => self::UPPERCASE,
            'digits'    => self::DIGITS,
            'symbols'   => self::SYMBOLS,
            default     => throw new \InvalidArgumentException("Unknown character set '{$set}'."),
        };
        if ($excludeAmbiguous) {
            $chars = str_replace(str_split(self::AMBIGUOUS), '', $chars);
        }
        return $chars;
    }

    /**
     * @return array{length: int, lowercase: bool, uppercase: bool, digits: bool, symbols: bool, exclude_ambiguous: bool}
     */
    private static function builtinDefaults(): array
    {
        return [
            'length'            => self::DEFAULT_LENGTH,
            'lowercase'         => true,
            'uppercase'         => true,
            'digits'            => true,
            'symbols'           => true,
            'exclude_ambiguous' => true,
        ];
    }

    /**
     * @param array<string, mixed> $raw
     * @param array{length: int, lowercase: bool, uppercase: bool, digits: bool, symbols: bool, exclude_ambiguous: bool} $base
     * @return array{length: int, lowercase: bool, uppercase: bool, digits: bool, symbols: bool, exclude_ambiguous: bool}
     */
    private static function normalize(array $raw, array $base): array
    {
        $opts = $base;
        if (array_key_exists('length', $raw) && is_numeric($raw['length'])) {
            $opts['length'] = (int) $raw['length'];
        }
        foreach (['lowercase', 'uppercase', 'digits', 'symbols', 'exclude_ambiguous'] as $key) {
            if (array_key_exists($key, $raw)) {
                $opts[$key] = self::toBool($raw[$key]);
            }
        }
        $opts['length'] = max(self::minLength(), min(self::MAX_LENGTH, $opts['length']));
        return $opts;
    }

    /**
     * @param array{length: int, lowercase: bool, uppercase: bool, digits: bool, symbols: bool, exclude_ambiguous: bool} $opts
     */
    private static function hasAnySet(array $opts): bool
    {
        return $opts['lowercase'] || $opts['uppercase'] || $opts['digits'] || $opts['symbols'];
    }

    private static function toBool(mixed $value): bool
    {
        if (is_bool($value)) {
            return $value;
        }
        if (is_int($value) || is_float($value)) {
            return $value != 0;
        }
        $s = strtolower(trim((string) $value));
        return in_array($s, ['1', 'true', 'on', 'yes'], true);
    }

    private static function readSetting(string $key, string $fallback): string
    {
        $value = Config::get($key);
        return $value === null || $value === '' ? $fallback : (string) $value;
    }

    private static function pick(string $pool): string
    {
        return $pool[random_int(0, strlen($pool) - 1)];
    }
}
