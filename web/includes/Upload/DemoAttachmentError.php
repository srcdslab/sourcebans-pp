<?php
// SourceBans++ (c) 2014-2026 SourceBans++ Dev Team
// Licensed under the Elastic License 2.0.
// See LICENSE.txt for the full license text and THIRD-PARTY-NOTICES.txt for attributions.

declare(strict_types=1);

namespace Sbpp\Upload;

/**
 * Why {@see UploadHandler::checkDemoAttachment()} refused an uploaded
 * demo reference. Callers turn it into their own error shape (JSON
 * `ApiError` for `bans.add`, an inline form error on the edit-ban page).
 */
enum DemoAttachmentError: string
{
    /** One of the pair (disk name, original name) is missing. */
    case Incomplete = 'incomplete';
    /** The disk name isn't the 32-hex name the uploader generates. */
    case InvalidReference = 'invalid_reference';
    /** The original name is not UTF-8 or longer than `origname` (128). */
    case InvalidName = 'invalid_name';
    /** No regular file by that name inside SB_DEMOS (or a symlink). */
    case Missing = 'missing';
    /** Another ban or submission already uses that file. */
    case AlreadyAttached = 'already_attached';

    /** User-facing message. */
    public function message(): string
    {
        return match ($this) {
            self::Incomplete       => 'The demo upload is incomplete.',
            self::InvalidReference => 'The demo upload reference is invalid.',
            self::InvalidName      => 'The demo filename is invalid.',
            self::Missing          => 'The uploaded demo is no longer available.',
            self::AlreadyAttached  => 'This demo is already attached to another ban or submission.',
        };
    }

    /** Form field the error belongs to (`dname` for the name, `dfile` otherwise). */
    public function field(): string
    {
        return $this === self::InvalidName ? 'dname' : 'dfile';
    }
}
