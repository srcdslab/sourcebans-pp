<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Security;

use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;

/**
 * QR code for the 2FA setup screen (#107), rendered server-side as SVG
 * (no GD / Imagick needed) and returned as a `data:` URI for an `<img>`:
 * an `<img>` never runs script, so the SVG can't be an XSS vector even
 * though it is built from the `otpauth://` URI.
 */
final class QrCode
{
    public static function svgDataUri(string $text, int $size = 200): string
    {
        $writer = new Writer(new ImageRenderer(new RendererStyle($size, 1), new SvgImageBackEnd()));
        return 'data:image/svg+xml;base64,' . base64_encode($writer->writeString($text));
    }
}
