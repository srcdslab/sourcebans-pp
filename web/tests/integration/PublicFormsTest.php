<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Tests\Integration;

use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use Sbpp\Tests\ApiTestCase;
use Sbpp\Tests\Fixture;
use Smarty\Smarty;

/**
 * #58: the public Protest a ban / Submit a ban forms accept every Steam ID
 * format they validate, don't treat archived protests as pending, and
 * don't reject IP-only reports because an unrelated IP ban exists.
 *
 * Each test POSTs through the real page handler in its own process (the
 * handlers declare top-level code that can only run once per process),
 * with a stub Smarty like Php82DeprecationsTest, then asserts on the rows
 * the handler wrote. SMTP is unconfigured in the test DB, so the admin
 * notification is attempted, logged and skipped.
 */
final class PublicFormsTest extends ApiTestCase
{
    private const STEAM2 = 'STEAM_0:1:12345';
    // 76561197960265728 + 12345 * 2 + 1
    private const STEAM64 = '76561197960290419';

    private function render(string $page, array $post): void
    {
        $GLOBALS['theme'] = new class extends Smarty {
            public function assign($tpl_var, $value = null, $nocache = false, $scope = null)
            {
                return $this;
            }

            public function display($template = null, $cache_id = null, $compile_id = null)
            {
                return '';
            }
        };
        $GLOBALS['userbank'] = new \CUserManager(null);
        $_SERVER['REMOTE_ADDR'] = '203.0.113.7';
        $_GET   = [];
        $_POST  = $post;
        $_FILES = [];

        ob_start();
        try {
            require ROOT . 'pages/' . $page;
        } finally {
            ob_end_clean();
        }
    }

    private function seedBan(string $authid, string $ip, int $type, int $length, int $ends): int
    {
        $pdo = Fixture::rawPdo();
        $pdo->prepare(sprintf(
            'INSERT INTO `%s_bans` (ip, authid, name, created, ends, length, reason, aid, adminIp, sid, type)
             VALUES (?, ?, ?, UNIX_TIMESTAMP(), ?, ?, ?, 0, ?, 0, ?)',
            DB_PREFIX,
        ))->execute([$ip, $authid, 'Player', $ends, $length, 'cheating', '127.0.0.1', $type]);
        return (int) $pdo->lastInsertId();
    }

    private function seedProtest(int $bid, int $archiv): void
    {
        Fixture::rawPdo()->prepare(sprintf(
            "INSERT INTO `%s_protests` (bid, datesubmitted, reason, email, archiv, pip) VALUES (?, UNIX_TIMESTAMP(), 'old', 'a@b.test', ?, '127.0.0.1')",
            DB_PREFIX,
        ))->execute([$bid, $archiv]);
    }

    /** @return list<int> bid of every protest row, oldest first */
    private function protestBids(): array
    {
        return array_map('intval', Fixture::rawPdo()
            ->query(sprintf('SELECT bid FROM `%s_protests` ORDER BY pid', DB_PREFIX))
            ->fetchAll(\PDO::FETCH_COLUMN));
    }

    private function submissionCount(): int
    {
        return (int) Fixture::rawPdo()
            ->query(sprintf('SELECT COUNT(*) FROM `%s_submissions`', DB_PREFIX))
            ->fetchColumn();
    }

    private static function protestPost(string $steam): array
    {
        return [
            'subprotest' => '1',
            'Type'       => '0',
            'SteamID'    => $steam,
            'PlayerName' => 'Player',
            'BanReason'  => 'Please unban me',
            'EmailAddr'  => 'player@example.test',
        ];
    }

    private static function submitPost(string $steam, string $ip): array
    {
        return [
            'subban'     => '1',
            'SteamID'    => $steam,
            'BanIP'      => $ip,
            'PlayerName' => 'Cheater',
            'BanReason'  => 'aimbot',
            'SubmitName' => 'Reporter',
            'EmailAddr'  => 'reporter@example.test',
            'server'     => '0',
        ];
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testProtestAcceptsSteamId64ForStoredSteam2Ban(): void
    {
        $bid = $this->seedBan(self::STEAM2, '', 0, 0, 0);

        $this->render('page.protest.php', self::protestPost(self::STEAM64));

        $this->assertSame([$bid], $this->protestBids());
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testProtestMatchesTheOtherUniverseDigit(): void
    {
        $bid = $this->seedBan('STEAM_1:1:12345', '', 0, 0, 0);

        $this->render('page.protest.php', self::protestPost(self::STEAM2));

        $this->assertSame([$bid], $this->protestBids());
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testArchivedProtestDoesNotBlockANewOne(): void
    {
        $bid = $this->seedBan(self::STEAM2, '', 0, 0, 0);
        $this->seedProtest($bid, 1);

        $this->render('page.protest.php', self::protestPost(self::STEAM2));

        $this->assertSame([$bid, $bid], $this->protestBids());
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testPendingProtestStillBlocksADuplicate(): void
    {
        $bid = $this->seedBan(self::STEAM2, '', 0, 0, 0);
        $this->seedProtest($bid, 0);

        $this->render('page.protest.php', self::protestPost(self::STEAM2));

        $this->assertSame([$bid], $this->protestBids());
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testProtestAttachesToTheActiveBanNotAnExpiredOne(): void
    {
        $active = $this->seedBan(self::STEAM2, '', 0, 0, 0);
        // Newer, but expired and not yet pruned.
        $this->seedBan(self::STEAM2, '', 0, 60, time() - 3600);

        $this->render('page.protest.php', self::protestPost(self::STEAM2));

        $this->assertSame([$active], $this->protestBids());
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testIpOnlySubmissionIgnoresPermanentIpBans(): void
    {
        $this->seedBan('', '198.51.100.9', 1, 0, 0);

        $this->render('page.submit.php', self::submitPost('', '198.51.100.20'));

        $this->assertSame(1, $this->submissionCount());
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testSubmissionForPermanentlyBannedSteamIdIsRejectedInAnyFormat(): void
    {
        $this->seedBan(self::STEAM2, '', 0, 0, 0);

        $this->render('page.submit.php', self::submitPost(self::STEAM64, ''));

        $this->assertSame(0, $this->submissionCount());
    }
}
