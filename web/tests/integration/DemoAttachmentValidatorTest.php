<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Tests\Integration;

use Sbpp\Tests\ApiTestCase;
use Sbpp\Tests\Fixture;
use Sbpp\Upload\DemoAttachmentError;
use Sbpp\Upload\UploadHandler;

/**
 * #98: `bans.add` and the edit-ban page link an uploaded demo through the
 * same validator, UploadHandler::checkDemoAttachment().
 */
final class DemoAttachmentValidatorTest extends ApiTestCase
{
    private const WEB = __DIR__ . '/../../';

    /** @var list<string> */
    private array $cleanup = [];

    protected function setUp(): void
    {
        parent::setUp();
        if (!is_dir(SB_DEMOS)) {
            mkdir(SB_DEMOS, 0775, true);
        }
    }

    protected function tearDown(): void
    {
        foreach ($this->cleanup as $path) {
            @unlink($path);
        }
        parent::tearDown();
    }

    private function upload(string $name): string
    {
        $path = SB_DEMOS . '/' . $name;
        file_put_contents($path, 'demo-bytes');
        $this->cleanup[] = $path;
        return $name;
    }

    private function check(string $diskName, string $originalName): ?DemoAttachmentError
    {
        return UploadHandler::checkDemoAttachment($GLOBALS['PDO'], $diskName, $originalName);
    }

    public function testNoAttachmentIsRecognised(): void
    {
        $this->assertFalse(UploadHandler::hasDemoAttachment('', ''));
        $this->assertFalse(UploadHandler::hasDemoAttachment('0', ''), 'The add-ban form sends 0 when nothing was uploaded.');
        $this->assertTrue(UploadHandler::hasDemoAttachment(str_repeat('a', 32), ''));
        $this->assertTrue(UploadHandler::hasDemoAttachment('', 'evidence.dem'));
    }

    public function testValidUploadPasses(): void
    {
        $name = $this->upload('98000000000000000000000000000001');
        $this->assertNull($this->check($name, 'evidence.dem'));
    }

    public function testRefusals(): void
    {
        $name = $this->upload('98000000000000000000000000000002');

        $this->assertSame(DemoAttachmentError::Incomplete, $this->check($name, ''));
        $this->assertSame(DemoAttachmentError::Incomplete, $this->check('0', 'evidence.dem'));
        $this->assertSame(DemoAttachmentError::InvalidReference, $this->check('../config.php', 'evidence.dem'));
        $this->assertSame(DemoAttachmentError::InvalidReference, $this->check('980000000000000000000000000000AB', 'evidence.dem'));
        $this->assertSame(DemoAttachmentError::InvalidName, $this->check($name, str_repeat('a', 129)));
        $this->assertSame(DemoAttachmentError::InvalidName, $this->check($name, "\xC3\x28.dem"));
        $this->assertSame(DemoAttachmentError::Missing, $this->check('98000000000000000000000000000099', 'evidence.dem'));
    }

    public function testSymlinkIsRefusedEvenWhenItPointsInsideTheDemoDir(): void
    {
        $target = $this->upload('98000000000000000000000000000003');
        $link = SB_DEMOS . '/98000000000000000000000000000004';
        @unlink($link);
        $this->assertTrue(symlink(SB_DEMOS . '/' . $target, $link));
        $this->cleanup[] = $link;

        $this->assertSame(DemoAttachmentError::Missing, $this->check('98000000000000000000000000000004', 'evidence.dem'));
    }

    public function testFileAlreadyAttachedToASubmissionOrBanIsRefused(): void
    {
        foreach (['S' => '98000000000000000000000000000005', 'B' => '98000000000000000000000000000006'] as $type => $name) {
            $this->upload($name);
            Fixture::rawPdo()->prepare(
                'INSERT INTO `' . DB_PREFIX . '_demos` (demid, demtype, filename, origname) VALUES (?, ?, ?, ?)'
            )->execute([7, $type, $name, 'private.dem']);

            $this->assertSame(DemoAttachmentError::AlreadyAttached, $this->check($name, 'evidence.dem'), $type);
        }
    }

    public function testBansAddRefusesADemoAlreadyAttachedToASubmission(): void
    {
        $this->loginAsAdmin();
        $name = $this->upload('98000000000000000000000000000007');
        Fixture::rawPdo()->prepare(
            'INSERT INTO `' . DB_PREFIX . "_demos` (demid, demtype, filename, origname) VALUES (3, 'S', ?, 'private.dem')"
        )->execute([$name]);

        $env = $this->api('bans.add', [
            'nickname' => 'Reused demo',
            'type'     => 0,
            'steam'    => 'STEAM_0:1:9800007',
            'ip'       => '',
            'length'   => 0,
            'dfile'    => $name,
            'dname'    => 'evidence.dem',
            'reason'   => 'demo validation',
            'fromsub'  => 0,
        ]);

        $this->assertEnvelopeError($env, 'validation');
        $this->assertSame('dfile', $env['error']['field']);
        $this->assertNull($this->row('bans', ['authid' => 'STEAM_0:1:9800007']));
    }

    public function testErrorFieldsMatchTheAddBanForm(): void
    {
        foreach (DemoAttachmentError::cases() as $case) {
            $this->assertSame($case === DemoAttachmentError::InvalidName ? 'dname' : 'dfile', $case->field());
            $this->assertNotSame('', $case->message());
        }
    }

    public function testBothCallersUseTheSharedValidator(): void
    {
        foreach (['api/handlers/bans.php', 'pages/admin.edit.ban.php'] as $file) {
            $src = (string) php_strip_whitespace(self::WEB . $file);
            $this->assertStringContainsString('UploadHandler::checkDemoAttachment(', $src, $file);
            $this->assertStringNotContainsString("preg_match('/^[a-f0-9]{32}\$/D'", $src, "$file must not keep its own copy");
        }
    }
}
