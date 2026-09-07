<?php

declare(strict_types=1);

namespace Helper;

class Notification extends \Prefab
{
    public const QPRINT_MAXL = 75;

    private const MAX_EMAIL_LENGTH = 254;
    private const MAX_SUBJECT_LENGTH = 998;
    private const MIME_BOUNDARY_BYTES = 24;

    /**
     * Convert a string to quoted-printable.
     */
    public function quotePrintEncode(string $str): string
    {
        return quoted_printable_encode($str);
    }

    /**
     * Send an email using UTF-8.
     *
     * Includes:
     * - recipient validation
     * - sender validation
     * - header injection protection
     * - cryptographically secure MIME boundary
     * - no MD5/SHA-1 usage
     */
    public function utf8mail(
        string $to,
        string $subject,
        string $body,
        ?string $text = null
    ): bool {
        $f3 = \Base::instance();

        $recipient = $this->validateEmail($to);

        if ($recipient === null) {
            return false;
        }

        $from = $this->validateEmail(
            (string) $f3->get('mail.from')
        );

        if ($from === null) {
            return false;
        }

        $subject = $this->sanitizeHeaderValue(
            $subject
        );

        if ($subject === '') {
            return false;
        }

        $headers = [];

        $headers[] = 'MIME-Version: 1.0';
        $headers[] = 'From: ' . $from;

        if (
            $text !== null
            && $text !== ''
        ) {
            /*
             * Cryptographically secure MIME boundary.
             *
             * Replaces the previous:
             * md5(date("r"))
             */
            $boundary =
                '=_phproject_'
                . bin2hex(
                    random_bytes(
                        self::MIME_BOUNDARY_BYTES
                    )
                );

            $headers[] =
                'Content-Type: multipart/alternative; boundary="'
                . $boundary
                . '"';

            $normalizedText =
                $this->normalizeMailLineEndings(
                    $text
                );

            $normalizedBody =
                $this->normalizeMailLineEndings(
                    $body
                );

            $encodedText =
                $this->quotePrintEncode(
                    $normalizedText
                );

            $encodedBody =
                $this->quotePrintEncode(
                    $normalizedBody
                );

            $message = '';

            $message .=
                '--'
                . $boundary
                . "\r\n";

            $message .=
                "Content-Type: text/plain; charset=utf-8\r\n";

            $message .=
                "Content-Transfer-Encoding: quoted-printable\r\n\r\n";

            $message .=
                $encodedText
                . "\r\n";

            $message .=
                '--'
                . $boundary
                . "\r\n";

            $message .=
                "Content-Type: text/html; charset=utf-8\r\n";

            $message .=
                "Content-Transfer-Encoding: quoted-printable\r\n\r\n";

            $message .=
                $encodedBody
                . "\r\n";

            $message .=
                '--'
                . $boundary
                . "--\r\n";

            $body = $message;
        } else {
            $headers[] =
                'Content-Type: text/html; charset=utf-8';

            $headers[] =
                'Content-Transfer-Encoding: quoted-printable';

            $body =
                $this->quotePrintEncode(
                    $this->normalizeMailLineEndings(
                        $body
                    )
                );
        }

        return mail(
            $recipient,
            $subject,
            $body,
            implode(
                "\r\n",
                $headers
            )
        );
    }

    /**
     * Send an email to watchers with the comment body.
     */
    public function issue_comment(
        int $issue_id,
        int $comment_id
    ): void {
        if (
            $issue_id <= 0
            || $comment_id <= 0
        ) {
            return;
        }

        $f3 = \Base::instance();

        if (!$f3->get('mail.from')) {
            return;
        }

        $log = new \Log(
            'mail.log'
        );

        $issue =
            new \Model\Issue();

        $issue->load(
            $issue_id
        );

        $comment =
            new \Model\Issue\Comment\Detail();

        $comment->load(
            $comment_id
        );

        if (
            !$issue->id
            || !$comment->id
        ) {
            return;
        }

        if ($issue->parent_id) {
            $parent =
                new \Model\Issue();

            $parent->load(
                $issue->parent_id
            );

            $f3->set(
                'parent',
                $parent
            );
        }

        $recipients =
            $this->_issue_watchers(
                $issue_id
            );

        $recipients =
            array_diff(
                $recipients,
                [
                    (string) $comment->user_email,
                ]
            );

        $f3->set(
            'issue',
            $issue
        );

        $f3->set(
            'comment',
            $comment
        );

        $f3->set(
            'previewText',
            $comment->text
        );

        $text =
            $this->_render(
                'notification/comment.txt'
            );

        $body =
            $this->_render(
                'notification/comment.html'
            );

        $subject =
            '[#'
            . (int) $issue->id
            . '] - New comment on '
            . $this->sanitizeSubjectPart(
                (string) $issue->name
            );

        foreach ($recipients as $recipient) {
            if (
                $this->utf8mail(
                    $recipient,
                    $subject,
                    $body,
                    $text
                )
            ) {
                /*
                 * Avoid writing PII/e-mail addresses
                 * into logs.
                 */
                $log->write(
                    'Comment notification sent.'
                );
            }
        }
    }

    /**
     * Send an email to watchers detailing updated fields.
     */
    public function issue_update(
        int $issue_id,
        int $update_id
    ): ?bool {
        if (
            $issue_id <= 0
            || $update_id <= 0
        ) {
            return false;
        }

        $f3 = \Base::instance();

        if (!$f3->get('mail.from')) {
            return null;
        }

        $log =
            new \Log(
                'mail.log'
            );

        $issue =
            new \Model\Issue();

        $issue->load(
            $issue_id
        );

        $update =
            new \Model\Custom(
                'issue_update_detail'
            );

        $update->load(
            $update_id
        );

        if (
            !$issue->id
            || !$update->id
        ) {
            return false;
        }

        $f3->set(
            'issue',
            $issue
        );

        if ($issue->parent_id) {
            $parent =
                new \Model\Issue();

            $parent->load(
                $issue->parent_id
            );

            $f3->set(
                'parent',
                $parent
            );
        }

        $changes =
            new \Model\Issue\Update\Field();

        $f3->set(
            'changes',
            $changes->find([
                'issue_update_id = ?',
                $update->id,
            ])
        );

        $recipients =
            $this->_issue_watchers(
                $issue_id
            );

        $recipients =
            array_diff(
                $recipients,
                [
                    (string) $update->user_email,
                ]
            );

        $f3->set(
            'update',
            $update
        );

        $text =
            $this->_render(
                'notification/update.txt'
            );

        $body =
            $this->_render(
                'notification/update.html'
            );

        $changes->load([
            "issue_update_id = ?
             AND `field` = 'closed_date'
             AND old_value = ''
             AND new_value != ''",
            $update->id,
        ]);

        $issueName =
            $this->sanitizeSubjectPart(
                (string) $issue->name
            );

        if (
            $changes
            && $changes->id
        ) {
            $subject =
                '[#'
                . (int) $issue->id
                . '] - '
                . $issueName
                . ' closed';
        } else {
            $subject =
                '[#'
                . (int) $issue->id
                . '] - '
                . $issueName
                . ' updated';
        }

        foreach ($recipients as $recipient) {
            if (
                $this->utf8mail(
                    $recipient,
                    $subject,
                    $body,
                    $text
                )
            ) {
                $log->write(
                    'Update notification sent.'
                );
            }
        }

        return null;
    }

    /**
     * Send an email to watchers when an issue is created.
     */
    public function issue_create(
        int $issue_id
    ): void {
        if ($issue_id <= 0) {
            return;
        }

        $f3 = \Base::instance();

        if (!$f3->get('mail.from')) {
            return;
        }

        $log =
            new \Log(
                'mail.log'
            );

        $issue =
            new \Model\Issue\Detail();

        $issue->load(
            $issue_id
        );

        if (!$issue->id) {
            return;
        }

        $f3->set(
            'issue',
            $issue
        );

        if ($issue->parent_id) {
            $parent =
                new \Model\Issue();

            $parent->load(
                $issue->parent_id
            );

            $f3->set(
                'parent',
                $parent
            );
        }

        $recipients =
            $this->_issue_watchers(
                $issue_id
            );

        $user =
            new \Model\User();

        $user->load(
            $issue->author_id
        );

        if (
            $user->id
            && $user->option(
                'disable_self_notifications'
            )
        ) {
            $recipients =
                array_diff(
                    $recipients,
                    [
                        (string) $user->email,
                    ]
                );
        }

        $text =
            $this->_render(
                'notification/new.txt'
            );

        $body =
            $this->_render(
                'notification/new.html'
            );

        $subject =
            '[#'
            . (int) $issue->id
            . '] - '
            . $this->sanitizeSubjectPart(
                (string) $issue->name
            )
            . ' created by '
            . $this->sanitizeSubjectPart(
                (string) $issue->author_name
            );

        foreach ($recipients as $recipient) {
            if (
                $this->utf8mail(
                    $recipient,
                    $subject,
                    $body,
                    $text
                )
            ) {
                $log->write(
                    'Create notification sent.'
                );
            }
        }
    }

    /**
     * Send an email to watchers when a file is attached.
     */
    public function issue_file(
        int $issue_id,
        int $file_id
    ): void {
        if (
            $issue_id <= 0
            || $file_id <= 0
        ) {
            return;
        }

        $f3 =
            \Base::instance();

        if (!$f3->get('mail.from')) {
            return;
        }

        $log =
            new \Log(
                'mail.log'
            );

        $issue =
            new \Model\Issue();

        $issue->load(
            $issue_id
        );

        $file =
            new \Model\Issue\File\Detail();

        $file->load(
            $file_id
        );

        if (
            !$issue->id
            || !$file->id
        ) {
            return;
        }

        /*
         * Ensure file belongs to the same issue.
         */
        if (
            (int) $file->issue_id
            !== (int) $issue->id
        ) {
            return;
        }

        if ($issue->parent_id) {
            $parent =
                new \Model\Issue();

            $parent->load(
                $issue->parent_id
            );

            $f3->set(
                'parent',
                $parent
            );
        }

        $recipients =
            $this->_issue_watchers(
                $issue_id
            );

        $recipients =
            array_diff(
                $recipients,
                [
                    (string) $file->user_email,
                ]
            );

        $f3->set(
            'issue',
            $issue
        );

        $f3->set(
            'file',
            $file
        );

        $f3->set(
            'previewText',
            $file->filename
        );

        $text =
            $this->_render(
                'notification/file.txt'
            );

        $body =
            $this->_render(
                'notification/file.html'
            );

        $subject =
            '[#'
            . (int) $issue->id
            . '] - '
            . $this->sanitizeSubjectPart(
                (string) $file->user_name
            )
            . ' attached a file to '
            . $this->sanitizeSubjectPart(
                (string) $issue->name
            );

        foreach ($recipients as $recipient) {
            if (
                $this->utf8mail(
                    $recipient,
                    $subject,
                    $body,
                    $text
                )
            ) {
                $log->write(
                    'File notification sent.'
                );
            }
        }
    }

    /**
     * Send a password-reset email.
     */
    public function user_reset(
        int $user_id,
        string $token
    ): void {
        if (
            $user_id <= 0
            || !$this->isValidResetToken(
                $token
            )
        ) {
            return;
        }

        $f3 =
            \Base::instance();

        if (!$f3->get('mail.from')) {
            return;
        }

        $user =
            new \Model\User();

        $user->load(
            $user_id
        );

        /*
         * Do not expose whether a user exists through
         * exception text from this helper.
         */
        if (
            !$user->id
            || $this->validateEmail(
                (string) $user->email
            ) === null
        ) {
            return;
        }

        $f3->set(
            'token',
            $token
        );

        $text =
            $this->_render(
                'notification/user_reset.txt'
            );

        $body =
            $this->_render(
                'notification/user_reset.html'
            );

        $siteName =
            $this->sanitizeSubjectPart(
                (string) $f3->get(
                    'site.name'
                )
            );

        $subject =
            'Reset your password - '
            . $siteName;

        $this->utf8mail(
            (string) $user->email,
            $subject,
            $body,
            $text
        );

        /*
         * Do not log the reset token or user email.
         */
    }

    /**
     * Send a user due/overdue issue email.
     */
    public function user_due_issues(
        \Model\User $user,
        array $due,
        array $overdue
    ): bool {
        $f3 =
            \Base::instance();

        if (!$f3->get('mail.from')) {
            return false;
        }

        $email =
            $this->validateEmail(
                (string) $user->email
            );

        if ($email === null) {
            return false;
        }

        $f3->set(
            'due',
            $due
        );

        $f3->set(
            'overdue',
            $overdue
        );

        $preview =
            count($due)
            . ' issues due today';

        if ($overdue !== []) {
            $preview .=
                ', '
                . count($overdue)
                . ' overdue issues';
        }

        $f3->set(
            'previewText',
            $preview
        );

        $siteName =
            $this->sanitizeSubjectPart(
                (string) $f3->get(
                    'site.name'
                )
            );

        $subject =
            'Due Today - '
            . $siteName;

        $text =
            $this->_render(
                'notification/user_due_issues.txt'
            );

        $body =
            $this->_render(
                'notification/user_due_issues.html'
            );

        return $this->utf8mail(
            $email,
            $subject,
            $body,
            $text
        );
    }

    /**
     * Get unique validated watcher email addresses.
     */
    protected function _issue_watchers(
        int $issue_id
    ): array {
        if ($issue_id <= 0) {
            return [];
        }

        $db =
            \Base::instance()
                ->get(
                    'db.instance'
                );

        if (!$db) {
            return [];
        }

        $recipients = [];

        /*
         * Author.
         */
        $result = $db->exec(
            'SELECT u.email
             FROM issue i
             INNER JOIN `user` u
                 ON i.author_id = u.id
             WHERE u.deleted_date IS NULL
               AND i.id = ?',
            $issue_id
        );

        if (
            !empty(
                $result[0]['email']
            )
        ) {
            $this->appendValidRecipient(
                $recipients,
                (string) $result[0]['email']
            );
        }

        /*
         * Owner.
         */
        $result = $db->exec(
            'SELECT u.email
             FROM issue i
             INNER JOIN `user` u
                 ON i.owner_id = u.id
             WHERE u.deleted_date IS NULL
               AND i.id = ?',
            $issue_id
        );

        if (
            !empty(
                $result[0]['email']
            )
        ) {
            $this->appendValidRecipient(
                $recipients,
                (string) $result[0]['email']
            );
        }

        /*
         * Determine whether the owner is a group.
         */
        $result = $db->exec(
            'SELECT u.role, u.id
             FROM issue i
             INNER JOIN `user` u
                 ON i.owner_id = u.id
             WHERE u.deleted_date IS NULL
               AND i.id = ?',
            $issue_id
        );

        if (
            !empty($result[0])
            && ($result[0]['role'] ?? null)
                === 'group'
        ) {
            $groupId =
                filter_var(
                    $result[0]['id'] ?? null,
                    FILTER_VALIDATE_INT,
                    [
                        'options' => [
                            'min_range' => 1,
                        ],
                    ]
                );

            if ($groupId !== false) {
                $groupUsers = $db->exec(
                    'SELECT g.user_email
                     FROM user_group_user g
                     WHERE g.deleted_date IS NULL
                       AND g.group_id = ?',
                    $groupId
                );

                foreach (
                    $groupUsers
                    as $groupUser
                ) {
                    if (
                        !empty(
                            $groupUser[
                                'user_email'
                            ]
                        )
                    ) {
                        $this->appendValidRecipient(
                            $recipients,
                            (string) $groupUser[
                                'user_email'
                            ]
                        );
                    }
                }
            }
        }

        /*
         * Issue watchers.
         */
        $watchers = $db->exec(
            'SELECT u.email
             FROM issue_watcher w
             INNER JOIN `user` u
                 ON w.user_id = u.id
             WHERE u.deleted_date IS NULL
               AND w.issue_id = ?',
            $issue_id
        );

        foreach ($watchers as $watcher) {
            if (
                !empty(
                    $watcher['email']
                )
            ) {
                $this->appendValidRecipient(
                    $recipients,
                    (string) $watcher['email']
                );
            }
        }

        return array_values(
            array_unique(
                $recipients
            )
        );
    }

    /**
     * Render a notification template.
     */
    protected function _render(
        string $file,
        string $mime = 'text/html',
        ?array $hive = null,
        int $ttl = 0
    ): string {
        if (
            !$this->isValidTemplatePath(
                $file
            )
        ) {
            throw new \InvalidArgumentException(
                'Invalid notification template.'
            );
        }

        return \Helper\View::instance()
            ->render(
                $file,
                $mime,
                $hive,
                $ttl
            );
    }

    /**
     * Normalize line endings to RFC-style CRLF.
     */
    private function normalizeMailLineEndings(
        string $value
    ): string {
        $value = str_replace(
            [
                "\r\n",
                "\r",
            ],
            "\n",
            $value
        );

        return str_replace(
            "\n",
            "\r\n",
            $value
        );
    }

    /**
     * Validate email address.
     */
    private function validateEmail(
        string $email
    ): ?string {
        $email =
            trim($email);

        if (
            $email === ''
            || strlen($email)
                > self::MAX_EMAIL_LENGTH
            || preg_match(
                '/[\r\n]/',
                $email
            )
        ) {
            return null;
        }

        $validated =
            filter_var(
                $email,
                FILTER_VALIDATE_EMAIL
            );

        return $validated === false
            ? null
            : $validated;
    }

    /**
     * Remove header control characters.
     */
    private function sanitizeHeaderValue(
        string $value
    ): string {
        $value =
            preg_replace(
                '/[\r\n\x00-\x08\x0B\x0C\x0E-\x1F\x7F]+/',
                ' ',
                $value
            ) ?? '';

        $value =
            trim(
                preg_replace(
                    '/\s+/u',
                    ' ',
                    $value
                ) ?? ''
            );

        return substr(
            $value,
            0,
            self::MAX_SUBJECT_LENGTH
        );
    }

    /**
     * Sanitize interpolated subject fragments.
     */
    private function sanitizeSubjectPart(
        string $value
    ): string {
        return $this->sanitizeHeaderValue(
            $value
        );
    }

    /**
     * Append only valid recipients.
     */
    private function appendValidRecipient(
        array &$recipients,
        string $email
    ): void {
        $validated =
            $this->validateEmail(
                $email
            );

        if ($validated !== null) {
            $recipients[] =
                $validated;
        }
    }

    /**
     * Reset tokens generated by the hardened User model
     * are 64 hexadecimal characters.
     */
    private function isValidResetToken(
        string $token
    ): bool {
        return strlen($token) === 64
            && ctype_xdigit(
                $token
            );
    }

    /**
     * Only allow known-style notification templates.
     *
     * Prevents path traversal if this method is reused
     * with dynamic input in the future.
     */
    private function isValidTemplatePath(
        string $file
    ): bool {
        if (
            $file === ''
            || strlen($file) > 255
            || str_contains(
                $file,
                "\0"
            )
            || str_contains(
                $file,
                '..'
            )
            || str_starts_with(
                $file,
                '/'
            )
            || str_starts_with(
                $file,
                '\\'
            )
        ) {
            return false;
        }

        return (bool) preg_match(
            '#^[a-zA-Z0-9/_\.-]+$#D',
            $file
        );
    }
}
