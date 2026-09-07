<?php

namespace Model;

/**
 * Class User
 *
 * @property int $id
 * @property ?string $username
 * @property ?string $email
 * @property string $name
 * @property ?string $password
 * @property ?string $salt
 * @property ?string $reset_token
 * @property string $role
 * @property int $rank
 * @property string $task_color
 * @property ?string $theme
 * @property ?string $language
 * @property ?string $avatar_filename
 * @property ?string $options
 * @property ?string $api_key
 * @property int $api_visible
 * @property string $created_date
 * @property ?string $deleted_date
 */
class User extends \Model
{
    public const RANK_GUEST = 0;
    public const RANK_CLIENT = 1;
    public const RANK_USER = 2;
    public const RANK_MANAGER = 3;
    public const RANK_ADMIN = 4;
    public const RANK_SUPER = 5;

    private const RESET_TOKEN_HASH_ALGORITHM = 'sha384';
    private const RESET_TOKEN_HASH_LENGTH = 96;
    private const RESET_RANDOM_BYTES = 64;

    private const MIN_AVATAR_SIZE = 1;
    private const MAX_AVATAR_SIZE = 2048;

    protected $_table_name = 'user';

    protected $_groupUsers = null;

    /**
     * Load currently authenticated user.
     */
    public function loadCurrent(): static
    {
        $f3 = \Base::instance();

        $session = new Session();
        $session->loadCurrent();

        $userId = filter_var(
            $session->user_id ?? null,
            FILTER_VALIDATE_INT,
            [
                'options' => [
                    'min_range' => 1,
                ],
            ]
        );

        if ($userId === false) {
            return $this;
        }

        $this->load([
            'id = ? AND deleted_date IS NULL',
            $userId,
        ]);

        if (!$this->id) {
            return $this;
        }

        $f3->set('user', $this->cast());
        $f3->set('user_obj', $this);

        if ($this->exists('language') && $this->language) {
            $f3->set(
                'LANGUAGE',
                $this->sanitizeLanguage((string) $this->language)
            );
        }

        return $this;
    }

    /**
     * Get path to user's avatar or Gravatar.
     *
     * @return string|false
     */
    public function avatar(int $size = 80)
    {
        if (!$this->id) {
            return false;
        }

        $size = max(
            self::MIN_AVATAR_SIZE,
            min(self::MAX_AVATAR_SIZE, $size)
        );

        $avatarFilename = $this->sanitizeFilename(
            (string) $this->get('avatar_filename')
        );

        if ($avatarFilename !== '') {
            $avatarPath = sprintf(
                'uploads/avatars/%s',
                $avatarFilename
            );

            if (is_file($avatarPath)) {
                return sprintf(
                    '%s/avatar/%d-%d.png',
                    rtrim((string) \Base::instance()->get('BASE'), '/'),
                    $size,
                    (int) $this->id
                );
            }
        }

        $email = filter_var(
            (string) $this->get('email'),
            FILTER_VALIDATE_EMAIL
        );

        return \Helper\View::instance()->gravatar(
            $email !== false ? $email : '',
            $size
        );
    }

    /**
     * Load all active users.
     */
    public function getAll(): array
    {
        return $this->find(
            "deleted_date IS NULL AND role != 'group'",
            [
                'order' => 'name ASC',
            ]
        ) ?: [];
    }

    /**
     * Load all deleted users.
     */
    public function getAllDeleted(): array
    {
        return $this->find(
            "deleted_date IS NOT NULL AND role != 'group'",
            [
                'order' => 'name ASC',
            ]
        ) ?: [];
    }

    /**
     * Load all active groups.
     */
    public function getAllGroups(): array
    {
        return $this->find(
            "deleted_date IS NULL AND role = 'group'",
            [
                'order' => 'name ASC',
            ]
        ) ?: [];
    }

    /**
     * Get all users within a group.
     *
     * @return array|null
     */
    public function getGroupUsers(): ?array
    {
        if ($this->role !== 'group') {
            return null;
        }

        if ($this->_groupUsers !== null) {
            return $this->_groupUsers;
        }

        $groupId = $this->validatePositiveId($this->id);

        if ($groupId === null) {
            return $this->_groupUsers = [];
        }

        $groupModel = new User\Group();

        $groupUsers = $groupModel->find([
            'group_id = ?',
            $groupId,
        ]) ?: [];

        $userIds = [];

        foreach ($groupUsers as $groupUser) {
            $userId = $this->validatePositiveId(
                $groupUser->user_id ?? null
            );

            if ($userId !== null) {
                $userIds[] = $userId;
            }
        }

        $userIds = array_values(array_unique($userIds));

        if ($userIds === []) {
            return $this->_groupUsers = [];
        }

        $placeholders = implode(
            ',',
            array_fill(0, count($userIds), '?')
        );

        $result = $this->find([
            "id IN ({$placeholders}) AND deleted_date IS NULL",
            ...$userIds,
        ]);

        return $this->_groupUsers = $result ?: [];
    }

    /**
     * Get IDs of users within a group.
     *
     * @return array|null
     */
    public function getGroupUserIds(): ?array
    {
        $users = $this->getGroupUsers();

        if ($users === null) {
            return null;
        }

        $ids = [];

        foreach ($users as $user) {
            $userId = $this->validatePositiveId(
                $user->id ?? null
            );

            if ($userId !== null) {
                $ids[] = $userId;
            }
        }

        return array_values(array_unique($ids));
    }

    /**
     * Get all user and group IDs shared with the current user.
     */
    public function getSharedGroupUserIds(): array
    {
        $currentUserId = $this->validatePositiveId($this->id);

        if ($currentUserId === null) {
            return [];
        }

        $groupModel = new User\Group();

        $groups = $groupModel->find([
            'user_id = ?',
            $currentUserId,
        ]) ?: [];

        $groupIds = [];

        foreach ($groups as $group) {
            $groupId = $this->validatePositiveId(
                $group->group_id ?? null
            );

            if ($groupId !== null) {
                $groupIds[] = $groupId;
            }
        }

        $groupIds = array_values(array_unique($groupIds));

        if ($groupIds === []) {
            return [$currentUserId];
        }

        $placeholders = implode(
            ',',
            array_fill(0, count($groupIds), '?')
        );

        $memberships = $groupModel->find([
            "group_id IN ({$placeholders})",
            ...$groupIds,
        ]) ?: [];

        $ids = $groupIds;
        $ids[] = $currentUserId;

        foreach ($memberships as $membership) {
            $userId = $this->validatePositiveId(
                $membership->user_id ?? null
            );

            if ($userId !== null) {
                $ids[] = $userId;
            }
        }

        return array_values(array_unique($ids));
    }

    /**
     * Get all user options.
     */
    public function options(): array
    {
        if (
            $this->options === null
            || trim((string) $this->options) === ''
        ) {
            return [];
        }

        try {
            $decoded = json_decode(
                (string) $this->options,
                true,
                512,
                JSON_THROW_ON_ERROR
            );

            return is_array($decoded)
                ? $decoded
                : [];
        } catch (\JsonException $exception) {
            return [];
        }
    }

    /**
     * Get or set a user option.
     *
     * @param mixed $value
     *
     * @return mixed
     */
    public function option(string $key, $value = null)
    {
        $key = $this->sanitizeOptionKey($key);

        if ($key === '') {
            return $value === null
                ? null
                : $this;
        }

        $options = $this->options();

        if ($value === null) {
            return $options[$key] ?? null;
        }

        $options[$key] = $this->sanitizeOptionValue($value);

        try {
            $this->options = json_encode(
                $options,
                JSON_THROW_ON_ERROR
            );
        } catch (\JsonException $exception) {
            throw new \InvalidArgumentException(
                'Unable to encode user options.',
                0,
                $exception
            );
        }

        return $this;
    }

    /**
     * Send an email alert with issues due on the given date.
     */
    public function sendDueAlert(string $date = ''): bool
    {
        $userId = $this->validatePositiveId($this->id);

        if ($userId === null) {
            return false;
        }

        if ($date === '' || $date === '0') {
            $date = date(
                'Y-m-d',
                \Helper\View::instance()->utc2local()
            );
        }

        if (!$this->isValidDate($date)) {
            return false;
        }

        $ownerIds = [$userId];

        $groupModel = new User\Group();

        $groups = $groupModel->find([
            'user_id = ?',
            $userId,
        ]) ?: [];

        foreach ($groups as $group) {
            $groupId = $this->validatePositiveId(
                $group->group_id ?? null
            );

            if ($groupId !== null) {
                $ownerIds[] = $groupId;
            }
        }

        $ownerIds = array_values(array_unique($ownerIds));

        if ($ownerIds === []) {
            return false;
        }

        $placeholders = implode(
            ',',
            array_fill(0, count($ownerIds), '?')
        );

        $parameters = array_merge(
            [$date],
            $ownerIds
        );

        $issueModel = new Issue();

        $due = $issueModel->find(
            [
                "due_date = ?
                AND owner_id IN ({$placeholders})
                AND closed_date IS NULL
                AND deleted_date IS NULL",
                ...$parameters,
            ],
            [
                'order' => 'priority DESC',
            ]
        ) ?: [];

        $overdue = $issueModel->find(
            [
                "due_date < ?
                AND owner_id IN ({$placeholders})
                AND closed_date IS NULL
                AND deleted_date IS NULL",
                ...$parameters,
            ],
            [
                'order' => 'priority DESC',
            ]
        ) ?: [];

        if ($due === [] && $overdue === []) {
            return false;
        }

        $notification = new \Helper\Notification();

        return (bool) $notification->user_due_issues(
            $this,
            $due,
            $overdue
        );
    }

    /**
     * Get user statistics.
     *
     * @param int $time Lower timestamp limit.
     */
    public function stats(int $time = 0): array
    {
        $userId = $this->validatePositiveId($this->id);

        if ($userId === null) {
            return [
                'labels' => [],
                'spent' => [],
                'closed' => [],
                'created' => [],
            ];
        }

        $offset = (int) \Helper\View::instance()->timeoffset();

        if ($time <= 0) {
            $time = strtotime(
                '-2 weeks',
                time() + $offset
            );

            if ($time === false) {
                $time = time() - 1209600;
            }
        }

        $dateExpression = [
            'DATE(DATE_ADD(',
            ', INTERVAL :offset SECOND))',
        ];

        if (\Base::instance()->get('db.engine') === 'sqlite') {
            $dateExpression = [
                'DATE(',
                ", :offset || ' seconds')",
            ];
        }

        $date = date('Y-m-d H:i:s', $time);

        $parameters = [
            ':user' => $userId,
            ':offset' => $offset,
            ':date' => $date,
        ];

        $spent = $this->db->exec(
            "SELECT
                {$dateExpression[0]}u.created_date{$dateExpression[1]} AS `date`,
                SUM(f.new_value - f.old_value) AS `val`
            FROM issue_update u
            JOIN issue_update_field f
                ON u.id = f.issue_update_id
                AND f.field = 'hours_spent'
            WHERE
                u.user_id = :user
                AND u.created_date > :date
            GROUP BY `date`",
            $parameters
        ) ?: [];

        $closed = $this->db->exec(
            "SELECT
                {$dateExpression[0]}i.closed_date{$dateExpression[1]} AS `date`,
                COUNT(*) AS `val`
            FROM issue i
            WHERE
                i.owner_id = :user
                AND i.closed_date > :date
            GROUP BY `date`",
            $parameters
        ) ?: [];

        $created = $this->db->exec(
            "SELECT
                {$dateExpression[0]}i.created_date{$dateExpression[1]} AS `date`,
                COUNT(*) AS `val`
            FROM issue i
            WHERE
                i.author_id = :user
                AND i.created_date > :date
            GROUP BY `date`",
            $parameters
        ) ?: [];

        $dates = $this->_createDateRangeArray(
            date('Y-m-d', $time),
            date('Y-m-d', time() + $offset)
        );

        $result = [
            'labels' => [],
            'spent' => [],
            'closed' => [],
            'created' => [],
        ];

        foreach ($spent as $row) {
            if (!isset($row['date'], $row['val'])) {
                continue;
            }

            $result['spent'][(string) $row['date']] =
                (float) $row['val'];
        }

        foreach ($closed as $row) {
            if (!isset($row['date'], $row['val'])) {
                continue;
            }

            $result['closed'][(string) $row['date']] =
                (int) $row['val'];
        }

        foreach ($created as $row) {
            if (!isset($row['date'], $row['val'])) {
                continue;
            }

            $result['created'][(string) $row['date']] =
                (int) $row['val'];
        }

        foreach ($dates as $dateValue) {
            $dateValue = (string) $dateValue;

            if (!$this->isValidDate($dateValue)) {
                continue;
            }

            $timestamp = strtotime($dateValue);

            if ($timestamp === false) {
                continue;
            }

            $result['labels'][$dateValue] =
                date('D j', $timestamp);

            $result['spent'][$dateValue] ??= 0.0;
            $result['closed'][$dateValue] ??= 0;
            $result['created'][$dateValue] ??= 0;
        }

        foreach ($result as &$values) {
            ksort($values);
        }

        unset($values);

        return $result;
    }

    /**
     * Reassign open issues.
     *
     * @throws \RuntimeException
     * @throws \InvalidArgumentException
     */
    public function reassignIssues(?int $userId): int
    {
        $currentUserId = $this->validatePositiveId($this->id);

        if ($currentUserId === null) {
            throw new \RuntimeException(
                'User is not initialized.'
            );
        }

        if (
            $userId !== null
            && $this->validatePositiveId($userId) === null
        ) {
            throw new \InvalidArgumentException(
                'Invalid target user identifier.'
            );
        }

        $issueModel = new Issue();

        $issues = $issueModel->find([
            'owner_id = ?
            AND deleted_date IS NULL
            AND closed_date IS NULL',
            $currentUserId,
        ]) ?: [];

        foreach ($issues as $issue) {
            $issue->owner_id = $userId;
            $issue->save();
        }

        return count($issues);
    }

    /**
     * Get date picker language.
     */
    public function date_picker(): object
    {
        $language = $this->language
            ?: \Base::instance()->get('LANGUAGE');

        $language = $this->sanitizeLanguage(
            (string) $language
        );

        return (object) [
            'language' => $language,
            'js' => $language !== 'en',
        ];
    }

    /**
     * Generate a cryptographically secure password reset token.
     */
    public function generateResetToken(): string
    {
        $random = random_bytes(self::RESET_RANDOM_BYTES);

        $token = hash(
            self::RESET_TOKEN_HASH_ALGORITHM,
            $random
        ) . (string) time();

        $this->reset_token = hash(
            self::RESET_TOKEN_HASH_ALGORITHM,
            $token
        );

        return $token;
    }

    /**
     * Validate a plaintext password reset token.
     */
    public function validateResetToken(string $token): bool
    {
        $token = trim($token);

        if (
            $token === ''
            || strlen($token) <= self::RESET_TOKEN_HASH_LENGTH
            || empty($this->reset_token)
        ) {
            return false;
        }

        /*
         * Tokens generated by generateResetToken() contain:
         * 96 hexadecimal SHA-384 characters + Unix timestamp.
         */
        if (
            !preg_match(
                '/^[a-f0-9]{96}[0-9]+$/D',
                $token
            )
        ) {
            return false;
        }

        $ttl = filter_var(
            \Base::instance()->get('security.reset_ttl'),
            FILTER_VALIDATE_INT,
            [
                'options' => [
                    'min_range' => 1,
                ],
            ]
        );

        if ($ttl === false) {
            return false;
        }

        $timestampPart = substr(
            $token,
            self::RESET_TOKEN_HASH_LENGTH
        );

        if (
            $timestampPart === ''
            || !ctype_digit($timestampPart)
        ) {
            return false;
        }

        $timestamp = (int) $timestampPart;
        $currentTime = time();

        if (
            $timestamp > $currentTime
            || $timestamp < ($currentTime - $ttl)
        ) {
            return false;
        }

        $expectedHash = (string) $this->reset_token;

        if (
            strlen($expectedHash) !== self::RESET_TOKEN_HASH_LENGTH
            || !ctype_xdigit($expectedHash)
        ) {
            return false;
        }

        $providedHash = hash(
            self::RESET_TOKEN_HASH_ALGORITHM,
            $token
        );

        return hash_equals(
            strtolower($expectedHash),
            $providedHash
        );
    }

    /**
     * Validate a positive numeric identifier.
     */
    private function validatePositiveId($value): ?int
    {
        $id = filter_var(
            $value,
            FILTER_VALIDATE_INT,
            [
                'options' => [
                    'min_range' => 1,
                ],
            ]
        );

        return $id === false
            ? null
            : $id;
    }

    /**
     * Sanitize a filename and prevent path traversal.
     */
    private function sanitizeFilename(string $filename): string
    {
        $filename = trim($filename);

        if ($filename === '') {
            return '';
        }

        $filename = basename($filename);

        return preg_replace(
            '/[^a-zA-Z0-9._-]/',
            '',
            $filename
        ) ?? '';
    }

    /**
     * Sanitize an option key.
     */
    private function sanitizeOptionKey(string $key): string
    {
        $key = trim($key);

        if ($key === '') {
            return '';
        }

        /*
         * Option names are identifiers, therefore control
         * characters and unexpected symbols are rejected.
         */
        $key = preg_replace(
            '/[^a-zA-Z0-9_.-]/',
            '',
            $key
        );

        if ($key === null) {
            return '';
        }

        return substr($key, 0, 128);
    }

    /**
     * Sanitize values stored in user options.
     *
     * Scalar strings have null/control characters removed.
     * Arrays are sanitized recursively.
     *
     * @param mixed $value
     *
     * @return mixed
     */
    private function sanitizeOptionValue($value)
    {
        if (is_string($value)) {
            $value = preg_replace(
                '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u',
                '',
                $value
            );

            return $value ?? '';
        }

        if (is_array($value)) {
            $sanitized = [];

            foreach ($value as $key => $item) {
                $cleanKey = is_string($key)
                    ? $this->sanitizeOptionKey($key)
                    : $key;

                if ($cleanKey === '') {
                    continue;
                }

                $sanitized[$cleanKey] =
                    $this->sanitizeOptionValue($item);
            }

            return $sanitized;
        }

        if (
            $value === null
            || is_bool($value)
            || is_int($value)
            || is_float($value)
        ) {
            return $value;
        }

        throw new \InvalidArgumentException(
            'Unsupported option value type.'
        );
    }

    /**
     * Validate Y-m-d formatted date.
     */
    private function isValidDate(string $date): bool
    {
        if (
            !preg_match(
                '/^\d{4}-\d{2}-\d{2}$/D',
                $date
            )
        ) {
            return false;
        }

        $dateObject = \DateTimeImmutable::createFromFormat(
            '!Y-m-d',
            $date
        );

        return $dateObject !== false
            && $dateObject->format('Y-m-d') === $date;
    }

    /**
     * Sanitize language configuration.
     */
    private function sanitizeLanguage(string $language): string
    {
        $language = explode(
            ',',
            $language,
            2
        )[0];

        $language = trim($language);

        if (
            $language === ''
            || !preg_match(
                '/^[a-zA-Z]{2,3}(?:[-_][a-zA-Z]{2,4})?$/D',
                $language
            )
        ) {
            return 'en';
        }

        return $language;
    }
}
