<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Rest;

use Sbpp\Api\ApiError;
use Sbpp\Config;
use Sbpp\Db\Database;
use Sbpp\Export\EntityExporter;
use Sbpp\Log;
use LogType;

/**
 * REST panel settings. Dedicated queries. Never returns or writes
 * `smtp.pass` or `telemetry.instance_id`.
 */
final class SettingsService
{
    /**
     * @return array<string, string>
     */
    public function get(): array
    {
        return $this->allVisible();
    }

    /**
     * @param array<string|int, mixed> $body
     * @return array<string, string>
     */
    public function patch(array $body): array
    {
        if ($body === []) {
            throw new ApiError('validation', 'Send at least one setting key.', null, 400);
        }

        $pdo = $this->db();
        $known = [];
        foreach ($pdo->query('SELECT `setting` FROM `:prefix_settings`')->resultset() as $row) {
            $name = (string) ($row['setting'] ?? '');
            if ($name !== '') {
                $known[$name] = true;
            }
        }

        $changed = [];
        foreach ($body as $key => $value) {
            if (!is_string($key) || $key === '') {
                throw new ApiError('validation', 'Setting keys must be strings.', null, 400);
            }
            if (in_array($key, EntityExporter::FORBIDDEN_SETTING_KEYS, true)) {
                throw new ApiError('validation', 'That setting cannot be read or written.', $key, 400);
            }
            if (!isset($known[$key])) {
                throw new ApiError('validation', 'Unknown setting.', $key, 400);
            }
            $stored = $this->stringify($value, $key);
            $pdo->query('UPDATE `:prefix_settings` SET `value` = :value WHERE `setting` = :setting');
            $pdo->bind(':value', $stored);
            $pdo->bind(':setting', $key);
            $pdo->execute();
            $changed[] = $key;
        }

        Config::init($pdo);
        Log::add(
            LogType::Message,
            'Settings Updated',
            'REST updated: ' . implode(', ', $changed),
        );

        return $this->allVisible();
    }

    /**
     * @return array<string, string>
     */
    private function allVisible(): array
    {
        $forbidden = EntityExporter::FORBIDDEN_SETTING_KEYS;
        $placeholders = implode(',', array_fill(0, count($forbidden), '?'));
        $pdo = $this->db();
        $pdo->query(
            "SELECT `setting`, `value` FROM `:prefix_settings`"
            . " WHERE `setting` NOT IN ({$placeholders}) ORDER BY `setting`"
        );
        $i = 1;
        foreach ($forbidden as $key) {
            $pdo->bind($i++, $key);
        }
        $out = [];
        foreach ($pdo->resultset() as $row) {
            $name = (string) ($row['setting'] ?? '');
            if ($name === '') {
                continue;
            }
            $out[$name] = (string) ($row['value'] ?? '');
        }
        return $out;
    }

    private function stringify(mixed $value, string $key): string
    {
        if (is_array($value) || is_object($value)) {
            throw new ApiError('validation', 'Value must be a string, number, or boolean.', $key, 400);
        }
        if ($this->isBoolKey($key)) {
            return $this->stringifyBool($value, $key);
        }
        if ($this->isIntKey($key)) {
            return $this->stringifyInt($value, $key);
        }
        if (is_bool($value)) {
            return $value ? '1' : '0';
        }
        if (is_int($value) || is_float($value)) {
            return (string) $value;
        }
        if (is_string($value)) {
            if (strlen($value) > 65535) {
                throw new ApiError('validation', 'Value is too long.', $key, 400);
            }
            if (str_contains($value, "\0")) {
                throw new ApiError('validation', 'Value must not contain a null byte.', $key, 400);
            }
            return $value;
        }
        if ($value === null) {
            return '';
        }
        throw new ApiError('validation', 'Value must be a string, number, or boolean.', $key, 400);
    }

    private function stringifyBool(mixed $value, string $key): string
    {
        if ($value === true || $value === 1 || $value === '1' || $value === 'true') {
            return '1';
        }
        if ($value === false || $value === 0 || $value === '0' || $value === 'false' || $value === '') {
            return '0';
        }
        throw new ApiError('validation', 'Must be 0 or 1.', $key, 400);
    }

    private function stringifyInt(mixed $value, string $key): string
    {
        if (is_bool($value) || $value === null || $value === '') {
            throw new ApiError('validation', 'Must be an integer.', $key, 400);
        }
        if (is_int($value)) {
            $n = $value;
        } elseif (is_float($value)) {
            if ($value !== floor($value)) {
                throw new ApiError('validation', 'Must be an integer.', $key, 400);
            }
            $n = (int) $value;
        } elseif (is_string($value) && preg_match('/^-?\d+$/', $value) === 1) {
            $n = (int) $value;
        } else {
            throw new ApiError('validation', 'Must be an integer.', $key, 400);
        }
        if ($n < 0) {
            throw new ApiError('validation', 'Must be zero or greater.', $key, 400);
        }
        return (string) $n;
    }

    private function isBoolKey(string $key): bool
    {
        if (str_starts_with($key, 'config.enable')) {
            return true;
        }
        return in_array($key, [
            'dash.lognopopup',
            'banlist.hideadminname',
            'banlist.nocountryfetch',
            'banlist.hideplayerips',
            'config.debug',
            'config.exportpublic',
            'protest.emailonlyinvolved',
            'telemetry.enabled',
        ], true);
    }

    private function isIntKey(string $key): bool
    {
        return str_starts_with($key, 'auth.maxlife')
            || $key === 'banlist.bansperpage'
            || $key === 'config.password.minlength'
            || $key === 'config.defaultpage';
    }

    private function db(): Database
    {
        $pdo = $GLOBALS['PDO'] ?? null;
        if ($pdo instanceof Database) {
            return $pdo;
        }
        return new Database(DB_HOST, (int) DB_PORT, DB_NAME, DB_USER, DB_PASS, DB_PREFIX, DB_CHARSET);
    }
}
