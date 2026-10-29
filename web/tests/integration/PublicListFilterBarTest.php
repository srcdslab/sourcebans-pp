<?php

declare(strict_types=1);

namespace Sbpp\Tests\Integration;

use PHPUnit\Framework\Attributes\PreserveGlobalState;
use PHPUnit\Framework\Attributes\RunInSeparateProcess;
use Sbpp\Tests\ApiTestCase;
use Sbpp\Tests\Fixture;
use Smarty\Smarty;

/**
 * The server / time selects in the public banlist + commslist filter
 * bar must narrow the list.
 *
 *   - Banlist: the filter form always submits `searchText=` (empty), so
 *     every Apply landed in the search branch, whose WHERE was
 *     `A OR B OR C OR D AND <filters>` with no parens. SQL precedence
 *     bound the filters to the last OR arm only, and the empty search
 *     matched every row through the other arms: server, time, state and
 *     hide-inactive were all no-ops.
 *   - Commslist: the handler never read `?server=` / `?time=` at all.
 *
 * Each test renders the page handler against a capturing stub Smarty
 * and reads the View properties (`ban_list`, `total_bans`,
 * `searchlink`) so both the paginated SELECT and the COUNT query are
 * pinned without depending on template markup. Process isolation
 * because both handlers declare top-level functions.
 */
final class PublicListFilterBarTest extends ApiTestCase
{
    private const SID_A = 901;
    private const SID_B = 902;

    /** @var array<string, int> label => bid */
    private array $ids = [];

    private object $theme;

    protected function setUp(): void
    {
        parent::setUp();
        $this->loginAsAdmin();
        $this->theme = $this->makeCapturingTheme();
        $GLOBALS['theme']    = $this->theme;
        $GLOBALS['username'] = 'admin';
    }

    protected function tearDown(): void
    {
        $_GET     = [];
        $_SESSION = [];
        unset($GLOBALS['theme']);
        parent::tearDown();
    }

    // -- Banlist ---------------------------------------------------------

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testBanlistServerFilterAppliesWithEmptySearchText(): void
    {
        $this->seedBans();
        $_GET = ['p' => 'banlist', 'searchText' => '', 'server' => (string) self::SID_A, 'time' => ''];

        $this->renderPage('banlist');

        $this->assertSameIds(['a_recent', 'a_old'], 'empty search + server=A');
        $this->assertSame(2, $this->theme->captured['total_bans'], 'count query must apply the server filter too');
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testBanlistTimeFilterAppliesWithEmptySearchText(): void
    {
        $this->seedBans();
        $_GET = ['p' => 'banlist', 'searchText' => '', 'server' => '', 'time' => '7d'];

        $this->renderPage('banlist');

        $this->assertSameIds(['a_recent', 'b_recent'], 'empty search + time=7d');
        $this->assertSame(2, $this->theme->captured['total_bans']);
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testBanlistFiltersBindToEveryArmOfANonEmptySearch(): void
    {
        $this->seedBans();
        // `FilterBar` hits the name arm on every seeded row, `reason`
        // hits the reason arm, so a filter that only bound the last
        // arm would still leak rows through the name arm.
        $_GET = ['p' => 'banlist', 'searchText' => 'FilterBar', 'server' => (string) self::SID_B, 'time' => '7d'];

        $this->renderPage('banlist');

        $this->assertSameIds(['b_recent'], 'search + server=B + time=7d');
        $this->assertSame(1, $this->theme->captured['total_bans']);
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testBanlistStateChipAppliesWithEmptySearchText(): void
    {
        $this->seedBans();
        $_GET = ['p' => 'banlist', 'searchText' => '', 'state' => 'unbanned'];

        $this->renderPage('banlist');

        $this->assertSameIds(['a_old'], 'empty search + state=unbanned');
    }

    // -- Commslist -------------------------------------------------------

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testCommslistServerFilterApplies(): void
    {
        $this->seedComms();
        $_GET = ['p' => 'commslist', 'server' => (string) self::SID_A];

        $this->renderPage('commslist');

        $this->assertSameIds(['a_recent', 'a_old'], 'server=A');
        $this->assertSame(2, $this->theme->captured['total_bans']);
        $this->assertStringContainsString('&server=' . self::SID_A, $this->theme->captured['searchlink'],
            'searchlink feeds pagination + the hide-inactive toggle, it must keep the server');
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testCommslistTimeFilterApplies(): void
    {
        $this->seedComms();
        $_GET = ['p' => 'commslist', 'time' => '7d'];

        $this->renderPage('commslist');

        $this->assertSameIds(['a_recent', 'b_recent'], 'time=7d');
        $this->assertSame(2, $this->theme->captured['total_bans']);
        $this->assertStringContainsString('&time=7d', $this->theme->captured['searchlink']);
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testCommslistFiltersComposeWithSearchAndTypeChip(): void
    {
        $this->seedComms();
        $_GET = ['p' => 'commslist', 'searchText' => '', 'server' => (string) self::SID_B, 'time' => '7d', 'type' => 'gag'];

        $this->renderPage('commslist');

        $this->assertSameIds(['b_recent'], 'empty search + server=B + time=7d + type=gag');
        $this->assertSame(1, $this->theme->captured['total_bans']);
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testCommslistFiltersApplyToAdvancedSearch(): void
    {
        $this->seedComms();
        $_GET = ['p' => 'commslist', 'advSearch' => 'FilterBar', 'advType' => 'name', 'server' => (string) self::SID_A];

        $this->renderPage('commslist');

        $this->assertSameIds(['a_recent', 'a_old'], 'advSearch name + server=A');
        $this->assertSame(2, $this->theme->captured['total_bans']);
    }

    #[RunInSeparateProcess]
    #[PreserveGlobalState(false)]
    public function testCommslistAdvancedSearchNoOpWithHideInactiveStillBuildsAWhere(): void
    {
        $this->seedComms();
        // Unknown advType resolves to an empty $where. With hide-inactive
        // on, the query used to end in a bare ` AND (…)` with no WHERE.
        $_SESSION['hideinactive'] = true;
        $_GET = ['p' => 'commslist', 'advSearch' => 'x', 'advType' => 'nope', 'server' => (string) self::SID_A];

        $this->renderPage('commslist');

        $this->assertSameIds(['a_recent'], 'hide-inactive + no-op advType + server=A');
    }

    // -- Helpers ---------------------------------------------------------

    /**
     * Four rows per table: server A / B x recent (1h ago) / old (10d
     * ago). The old server-A row is admin-lifted so state + hide-inactive
     * filters have something to drop.
     */
    private function seedBans(): void
    {
        $pdo  = Fixture::rawPdo();
        $now  = time();
        $aid  = Fixture::adminAid();
        $stmt = $pdo->prepare(sprintf(
            'INSERT INTO `%s_bans` (type, ip, authid, name, created, ends, length, reason, aid, sid, RemovedBy, RemovedOn, RemoveType)
             VALUES (0, NULL, ?, ?, ?, 0, 0, ?, ?, ?, ?, ?, ?)',
            DB_PREFIX,
        ));
        foreach ($this->rowSpecs($now, $aid) as $label => [$sid, $created, $removedBy, $removedOn, $removeType]) {
            $stmt->execute([
                'STEAM_0:1:' . (73000 + count($this->ids)),
                'FilterBar ' . $label,
                $created,
                'reason ' . $label,
                $aid,
                $sid,
                $removedBy,
                $removedOn,
                $removeType,
            ]);
            $this->ids[$label] = (int) $pdo->lastInsertId();
        }
    }

    private function seedComms(): void
    {
        $pdo  = Fixture::rawPdo();
        $now  = time();
        $aid  = Fixture::adminAid();
        $stmt = $pdo->prepare(sprintf(
            'INSERT INTO `%s_comms` (type, authid, name, created, ends, length, reason, aid, sid, RemovedBy, RemovedOn, RemoveType)
             VALUES (?, ?, ?, ?, 0, 0, ?, ?, ?, ?, ?, ?)',
            DB_PREFIX,
        ));
        foreach ($this->rowSpecs($now, $aid) as $label => [$sid, $created, $removedBy, $removedOn, $removeType]) {
            $stmt->execute([
                $sid === self::SID_B ? 2 : 1, // server B rows are gags, server A rows mutes
                'STEAM_0:1:' . (74000 + count($this->ids)),
                'FilterBar ' . $label,
                $created,
                'reason ' . $label,
                $aid,
                $sid,
                $removedBy,
                $removedOn,
                $removeType,
            ]);
            $this->ids[$label] = (int) $pdo->lastInsertId();
        }
    }

    /**
     * @return array<string, array{int, int, ?int, ?int, ?string}>
     *         label => [sid, created, RemovedBy, RemovedOn, RemoveType]
     */
    private function rowSpecs(int $now, int $aid): array
    {
        $day = 86400;
        return [
            'a_recent' => [self::SID_A, $now - 3600,     null, null, null],
            'a_old'    => [self::SID_A, $now - 10 * $day, $aid, $now - $day, 'U'],
            'b_recent' => [self::SID_B, $now - 3600,     null, null, null],
            'b_old'    => [self::SID_B, $now - 10 * $day, null, null, null],
        ];
    }

    /** @param list<string> $expectedLabels */
    private function assertSameIds(array $expectedLabels, string $case): void
    {
        $expected = array_map(fn (string $l): int => $this->ids[$l], $expectedLabels);
        $actual   = array_map(
            static fn (array $row): int => (int) $row['ban_id'],
            $this->theme->captured['ban_list'] ?? [],
        );
        sort($expected);
        sort($actual);
        $this->assertSame($expected, $actual, "Rows rendered for {$case}");
    }

    private function renderPage(string $page): void
    {
        ob_start();
        try {
            (function () use ($page): void {
                global $userbank, $theme;
                $userbank = $GLOBALS['userbank'];
                $theme    = $GLOBALS['theme'];
                require ROOT . 'pages/page.' . $page . '.php';
            })();
        } finally {
            ob_end_clean();
        }
    }

    private function makeCapturingTheme(): Smarty
    {
        return new class extends Smarty {
            /** @var array<string, mixed> */
            public array $captured = [];

            /** @phpstan-ignore method.childParameterType */
            public function assign($tpl_var, $value = null, $nocache = false, $scope = null)
            {
                if (is_string($tpl_var)) {
                    $this->captured[$tpl_var] = $value;
                }
                return $this;
            }

            public function display($template = null, $cache_id = null, $compile_id = null)
            {
                return '';
            }
        };
    }
}
