<?php

namespace Sbpp\Auth\Handler;

use Sbpp\Config;
use Sbpp\Db\Database;

/**
 * Checks a username + password. It no longer starts the session itself
 * (#107): the caller passes {@see aid()} / {@see maxlife()} to
 * {@see \Sbpp\Auth\TwoFactor::completePrimary()}, which asks for the
 * second factor first when the admin has one.
 */
final class NormalAuthHandler
{
    private bool $result = false;
    private int $aid = 0;
    private int $maxlife = 0;

    public function __construct(
        private Database $dbs,
        string $username, string $password, bool $remember
    )
    {
        $user = $this->getInfosFromDatabase($username);

        $maxlife = (($remember) ? Config::get('auth.maxlife.remember') : Config::get('auth.maxlife')) * 60;

        if (!$user || empty($password))
            return;

        if (!empty($password) && (!empty($user['password']) || $user['password'] !== null)) {
            if ($this->checkPassword($password, $user['password'])) {
                $this->result = true;
            } elseif ($this->legacyPasswordCheck($password, $user['password'])) {
                $this->result = true;
                $this->updatePasswordHash($password, $user['aid']);
            }
            if ($this->result) {
                $this->aid = (int) $user['aid'];
                $this->maxlife = (int) $maxlife;
            }
        }
    }

    public function getResult(): bool
    {
        return $this->result;
    }

    /** The admin the password belongs to (0 unless {@see getResult()}). */
    public function aid(): int
    {
        return $this->aid;
    }

    /** Session lifetime in seconds (remember-me aware). */
    public function maxlife(): int
    {
        return $this->maxlife;
    }

    private function checkPassword(string $password, string $hash): bool
    {
        return (bool)(password_verify($password, $hash));
    }

    private function legacyPasswordCheck(string $password, string $hash): bool
    {
        $crypt = @crypt($password, SB_NEW_SALT);
        $sha1 = @sha1(sha1('SourceBans' . $password));

        return (bool)(hash_equals($crypt, $hash) || hash_equals($sha1, $hash));
    }

    private function updatePasswordHash(string $password, int $aid): bool
    {
        $this->dbs->query("UPDATE `:prefix_admins` SET password = :password WHERE aid = :aid");
        $this->dbs->bindMultiple([
            ':password' => password_hash($password, PASSWORD_BCRYPT),
            ':aid'      => $aid,
        ]);
        return $this->dbs->execute();
    }

    private function getInfosFromDatabase(string $username): mixed
    {
        $enabledSelect = \Sbpp\Auth\AdminsSchema::hasEnabledColumn($this->dbs)
            ? ', enabled'
            : '';
        $this->dbs->query("SELECT aid, password{$enabledSelect} FROM `:prefix_admins` WHERE user = :user");
        $this->dbs->bind(':user', $username);
        $row = $this->dbs->single();
        if (!is_array($row) || (int) ($row['enabled'] ?? 1) === 0) {
            return false;
        }
        return $row;
    }
}

// Issue #1290 phase B: legacy global-name shim. Procedural code keeps
// using `\NormalAuthHandler` until the call-site sweep PR.
class_alias(\Sbpp\Auth\Handler\NormalAuthHandler::class, 'NormalAuthHandler');
