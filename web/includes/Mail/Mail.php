<?php

// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Mail;

use LogType;
use Sbpp\Log;
use Throwable;

final class Mail
{
    public static function send(
        array|string $destinations,
        EmailType $type,
        array $variables = [],
        ?string $customSubject = null): bool
    {
        $mailer = Mailer::create();
        if ($mailer === null) {
            // #1269: Mailer::create() returns null when smtp.host /
            // smtp.user / smtp.pass aren't configured — exactly the
            // state a freshly-upgraded 1.x panel is in (the legacy
            // PHP-mail() flow doesn't carry SMTP credentials forward).
            // Log the actionable cause once instead of letting the
            // dispatch below throw "Call to a member function send()
            // on null" which then gets caught as a generic mail
            // failure.
            Log::add(LogType::Error, 'Mail not configured', 'SMTP host / user / password are empty in sb_settings; configure them under Admin → Settings before sending mail.');
            return false;
        }

        try {
            $content = self::render($type, $variables);
            $mailer->send(
                destination: $destinations,
                subject: $customSubject ?? $type->subject(),
                body: $content
            );
        } catch (Throwable $e)
        {
            Log::add(LogType::Error, 'Mail error', $e->getMessage());
            return false;
        }

        return true;
    }

    /**
     * Fill a mail template. Every value is HTML-escaped and newlines become
     * `<br>`: several placeholders carry text typed into the anonymous
     * Submit / Protest forms, which would otherwise land as live HTML
     * (links, images, fake buttons) in every notified admin's inbox (#56).
     *
     * @param array<string, scalar|null> $variables placeholder (e.g. `{name}`) => plain-text value
     */
    public static function render(EmailType $type, array $variables): string
    {
        $path = self::templatePath($type);
        $template = is_readable($path) ? file_get_contents($path) : false;
        if ($template === false) {
            throw new \RuntimeException("Mail template not found: {$path}");
        }

        $values = array_map(
            static fn ($value): string => nl2br(htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'), false),
            array_values($variables),
        );

        return str_replace(array_keys($variables), $values, $template);
    }

    /**
     * The active theme's template, or the default theme's when the active
     * theme doesn't ship that file. Pre-#56 the condition was inverted:
     * custom templates were ignored, and a theme without them read a
     * missing file.
     */
    public static function templatePath(EmailType $type, ?string $theme = null): string
    {
        $file = 'mails' . DIRECTORY_SEPARATOR . $type->template() . '.html';
        $theme ??= SB_THEME;

        $path = SB_THEMES . $theme . DIRECTORY_SEPARATOR . $file;
        if ($theme !== 'default' && !is_readable($path)) {
            $path = SB_THEMES . 'default' . DIRECTORY_SEPARATOR . $file;
        }

        return $path;
    }
}