<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Sbpp\Mail\EmailType;
use Sbpp\Mail\Mail;

/**
 * #56: mail templates escape their variables and resolve the active
 * theme's template before falling back to the default theme's.
 */
final class MailRenderTest extends TestCase
{
    private ?string $tempTheme = null;

    protected function tearDown(): void
    {
        if ($this->tempTheme !== null) {
            $dir = SB_THEMES . $this->tempTheme;
            foreach (glob($dir . '/mails/*') ?: [] as $file) {
                unlink($file);
            }
            @rmdir($dir . '/mails');
            @rmdir($dir);
        }
        parent::tearDown();
    }

    private function makeTheme(bool $withSubmissionTemplate): string
    {
        $this->tempTheme = 'zz-mail-test-' . bin2hex(random_bytes(4));
        mkdir(SB_THEMES . $this->tempTheme . '/mails', 0777, true);
        if ($withSubmissionTemplate) {
            file_put_contents(
                SB_THEMES . $this->tempTheme . '/mails/' . EmailType::BanSubmission->template() . '.html',
                '<p>custom {name}</p>',
            );
        }
        return $this->tempTheme;
    }

    public function testRenderEscapesPublicFormInput(): void
    {
        $html = Mail::render(EmailType::BanSubmission, [
            '{name}'   => '<a href="https://evil.example">Login</a>',
            '{reason}' => '<img src="https://evil.example/pixel.gif">',
        ]);

        $this->assertStringNotContainsString('<a href="https://evil.example">', $html);
        $this->assertStringNotContainsString('<img src="https://evil.example', $html);
        $this->assertStringContainsString('&lt;a href=&quot;https://evil.example&quot;&gt;Login&lt;/a&gt;', $html);
    }

    public function testRenderEscapesUrlsForHrefAttributes(): void
    {
        $html = Mail::render(EmailType::PasswordReset, [
            '{link}' => 'https://panel.example/index.php?p=lostpassword&email=a%40b.c&validation=x"y',
            '{name}' => 'admin',
            '{home}' => 'https://panel.example',
        ]);

        $this->assertStringContainsString(
            'href="https://panel.example/index.php?p=lostpassword&amp;email=a%40b.c&amp;validation=x&quot;y"',
            $html,
        );
    }

    public function testRenderKeepsLineBreaks(): void
    {
        $html = Mail::render(EmailType::Custom, [
            '{message}' => "line one\nline two",
            '{subject}' => 's',
            '{admin}'   => 'a',
            '{home}'    => 'h',
        ]);

        $this->assertStringContainsString("line one<br>\nline two", $html);
    }

    public function testDefaultThemeUsesItsOwnTemplate(): void
    {
        $this->assertSame(
            SB_THEMES . 'default' . DIRECTORY_SEPARATOR . 'mails' . DIRECTORY_SEPARATOR . 'ban_submission.html',
            Mail::templatePath(EmailType::BanSubmission, 'default'),
        );
    }

    public function testCustomThemeTemplateWins(): void
    {
        $theme = $this->makeTheme(true);

        $this->assertSame(
            SB_THEMES . $theme . DIRECTORY_SEPARATOR . 'mails' . DIRECTORY_SEPARATOR . 'ban_submission.html',
            Mail::templatePath(EmailType::BanSubmission, $theme),
        );
    }

    public function testCustomThemeWithoutTemplateFallsBackToDefault(): void
    {
        $theme = $this->makeTheme(false);

        $path = Mail::templatePath(EmailType::BanSubmission, $theme);

        $this->assertSame(
            SB_THEMES . 'default' . DIRECTORY_SEPARATOR . 'mails' . DIRECTORY_SEPARATOR . 'ban_submission.html',
            $path,
        );
        $this->assertFileExists($path);
    }
}
