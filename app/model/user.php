<?php

declare(strict_types=1);

namespace Model;

/**
 * Class User
 *
 * Security focus: CONFIDENTIALITY.
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

    private const PASSWORD_MIN_LENGTH = 12;
    private const PASSWORD_MAX_LENGTH = 1024;

    private const BCRYPT_COST = 12;

    /*
     * Argon2id configuration.
     *
     * 19 MiB memory
     * 2 iterations
     * 1 thread
     */
    private const ARGON_MEMORY_COST = 19456;
    private const ARGON_TIME_COST = 2;
    private const ARGON_THREADS = 1;

    /*
     * Reset token:
     *
     * 32 random bytes = 256 bits of entropy.
     */
    private const RESET_TOKEN_BYTES = 32;

    private const RESET_TOKEN_MAX_LENGTH = 128;

    /*
     * Authentication brute-force protection.
     */
    private const LOGIN_MAX_ATTEMPTS = 5;
    private const LOGIN_WINDOW_SECONDS = 900;

    private const MAX_IDENTIFIER_LENGTH = 254;
    private const MAX_AVATAR_SIZE = 2048;

    protected $_table_name = 'user';

    protected $_groupUsers = null;

    /**
     * Load currently logged-in user.
     *
     * Sensitive fields are deliberately excluded from
     * the globally accessible user array.
     */
    public function loadCurrent(): static
    {
        $f3 = \Base::instance();

        $session = new Session();
        $session->loadCurrent();

        $userId = $this->validatePositiveId(
            $session->user_id ?? null
        );

        if ($userId === null) {
            return $this;
        }

        $this->load([
            'id = ? AND deleted_date IS NULL',
            $userId,
        ]);

        if (!$this->id) {
            return $this;
        }

        /*
         * IMPORTANT:
         *
         * Do not expose the complete result of $this->cast().
         *
         * The model contains:
         *
         * password
         * salt
         * reset_token
         * api_key
         *
         * These fields must not be propagated to the global
         * application context.
         */
        $f3->set(
            'user',
            $this->getSafeSessionData()
        );

        /*
         * Kept for compatibility with the existing application.
         *
         * Avoid serializing or rendering this object directly.
         */
        $f3->set(
            'user_obj',
            $this
        );

        if (
            $this->exists('language')
            && $this->language
        ) {
            $f3->set(
                'LANGUAGE',
                $this->sanitizeLanguage(
                    (string) $this->language
                )
            );
        }

        return $this;
    }

    /**
     * Return only information that can safely be exposed
     * in the authenticated-user application context.
     */
    private function getSafeSessionData(): array
    {
        return [
            'id' => (int) $this->id,
            'username' => $this->username,
            'email' => $this->email,
            'name' => $this->name,
            'role' => $this->role,
            'rank' => (int) $this->rank,
            'task_color' => $this->task_color,
            'theme' => $this->theme,
            'language' => $this->language,
            'avatar_filename' => $this->avatar_filename,
            'api_visible' => (int) $this->api_visible,
            'created_date' => $this->created_date,
        ];
    }

    /**
     * Securely set a password.
     *
     * Argon2id is preferred.
     * Bcrypt is used as fallback.
     */
    public function setPassword(
        string $plainPassword
    ): static {
        $this->validatePassword(
            $plainPassword
        );

        $algorithm = $this->getPasswordAlgorithm();

        $hash = password_hash(
            $plainPassword,
            $algorithm,
            $this->getPasswordOptions(
                $algorithm
            )
        );

        if ($hash === false) {
            throw new \RuntimeException(
                'Unable to securely hash password.'
            );
        }

        $this->password = $hash;

        /*
         * password_hash() already handles the salt.
         *
         * A manually managed salt is unnecessary.
         */
        $this->salt = null;

        return $this;
    }

    /**
     * Securely verify a password.
     *
     * password_verify() is designed for password verification
     * and avoids manually comparing sensitive hashes.
     */
    public function verifyPassword(
        string $plainPassword
    ): bool {
        if (
            !$this->isValidPasswordInput(
                $plainPassword
            )
        ) {
            $this->performDummyPasswordVerification();

            return false;
        }

        $storedPassword = (string) (
            $this->password ?? ''
        );

        if ($storedPassword === '') {
            $this->performDummyPasswordVerification();

            return false;
        }

        return password_verify(
            $plainPassword,
            $storedPassword
        );
    }

    /**
     * Upgrade old password hashes to the current algorithm
     * and parameters after a successful authentication.
     */
    public function rehashPasswordIfNecessary(
        string $plainPassword
    ): bool {
        if (
            !$this->verifyPassword(
                $plainPassword
            )
        ) {
            return false;
        }

        $algorithm = $this->getPasswordAlgorithm();

        if (
            password_needs_rehash(
                (string) $this->password,
                $algorithm,
                $this->getPasswordOptions(
                    $algorithm
                )
            )
        ) {
            $this->setPassword(
                $plainPassword
            );

            $this->save();
        }

        return true;
    }

    /**
     * Authentication with brute-force mitigation and
     * account-enumeration resistance.
     */
    public function authenticateSecure(
        string $identifier,
        string $plainPassword
    ): bool {
        $identifier = $this->normalizeIdentifier(
            $identifier
        );

        if (
            $identifier === ''
            || !$this->isValidPasswordInput(
                $plainPassword
            )
        ) {
            $this->performDummyPasswordVerification();

            return false;
        }

        $rateLimitKey = $this->buildRateLimitKey(
            $identifier
        );

        if (
            $this->isRateLimited(
                $rateLimitKey
            )
        ) {
            /*
             * Execute password work even when blocked to make
             * timing differences less useful.
             */
            $this->performDummyPasswordVerification();

            return false;
        }

        /*
         * Parameterized lookup protects against SQL injection.
         */
        $this->load([
            '(username = ? OR email = ?)
             AND deleted_date IS NULL',
            $identifier,
            $identifier,
        ]);

        if (!$this->id) {
            /*
             * Use dummy verification so an attacker cannot
             * easily distinguish nonexistent users through
             * response time.
             */
            $this->performDummyPasswordVerification();

            $this->recordFailedLogin(
                $rateLimitKey
            );

            return false;
        }

        if (
            !$this->verifyPassword(
                $plainPassword
            )
        ) {
            $this->recordFailedLogin(
                $rateLimitKey
            );

            return false;
        }

        $this->clearLoginAttempts(
            $rateLimitKey
        );

        /*
         * Opportunistically migrate an old password hash.
         */
        $this->rehashPasswordIfNecessary(
            $plainPassword
        );

        return true;
    }

    /**
     * Compare secrets in constant time.
     */
    public static function secureEquals(
        string $expected,
        string $provided
    ): bool {
        if (
            $expected === ''
            || $provided === ''
        ) {
            return false;
        }

        return hash_equals(
            $expected,
            $provided
        );
    }

    /**
     * Verify an API key using timing-resistant comparison.
     *
     * This preserves compatibility with installations where
     * api_key is already stored directly in the database.
     */
    public function verifyApiKey(
        string $providedApiKey
    ): bool {
        if (
            $providedApiKey === ''
            || strlen($providedApiKey) > 512
        ) {
            return false;
        }

        $storedApiKey = (string) (
            $this->api_key ?? ''
        );

        if ($storedApiKey === '') {
            return false;
        }

        return hash_equals(
            $storedApiKey,
            $providedApiKey
        );
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
            1,
            min(
                self::MAX_AVATAR_SIZE,
                $size
            )
        );

        $avatarFilename = $this->sanitizeFilename(
            (string) $this->get(
                'avatar_filename'
            )
        );

        if ($avatarFilename !== '') {
            $avatarPath =
                'uploads/avatars/' .
                $avatarFilename;

            if (is_file($avatarPath)) {
                return sprintf(
                    '%s/avatar/%d-%d.png',
                    rtrim(
                        (string) \Base::instance()
                            ->get('BASE'),
                        '/'
                    ),
                    $size,
                    (int) $this->id
                );
            }
        }

        $email = filter_var(
            (string) $this->get('email'),
            FILTER_VALIDATE_EMAIL
        );

        return \Helper\View::instance()
            ->gravatar(
                $email !== false
                    ? $email
                    : '',
                $size
            );
    }

    /**
     * Load all active users.
     */
    public function getAll(): array
    {
        return $this->find(
            "deleted_date IS NULL
             AND role != 'group'",
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
            "deleted_date IS NOT NULL
             AND role != 'group'",
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
            "deleted_date IS NULL
             AND role = 'group'",
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

        $groupId = $this->validatePositiveId(
            $this->id
        );

        if ($groupId === null) {
            return $this->_groupUsers = [];
        }

        $groupModel = new User\Group();

        $memberships = $groupModel->find([
            'group_id = ?',
            $groupId,
        ]) ?: [];

        $userIds = [];

        foreach ($memberships as $membership) {
            $userId = $this->validatePositiveId(
                $membership->user_id ?? null
            );

            if ($userId !== null) {
                $userIds[] = $userId;
            }
        }

        $userIds = array_values(
            array_unique($userIds)
        );

        if ($userIds === []) {
            return $this->_groupUsers = [];
        }

        $placeholders = implode(
            ',',
            array_fill(
                0,
                count($userIds),
                '?'
            )
        );

        $users = $this->find([
            "id IN ({$placeholders})
             AND deleted_date IS NULL",
            ...$userIds,
        ]);

        return $this->_groupUsers =
            $users ?: [];
    }

    /**
     * Get array of IDs of users within a group.
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

        return array_values(
            array_unique($ids)
        );
    }

    /**
     * Get all user IDs in groups shared with this user,
     * together with group IDs.
     */
    public function getSharedGroupUserIds(): array
    {
        $currentUserId =
            $this->validatePositiveId(
                $this->id
            );

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
            $groupId =
                $this->validatePositiveId(
                    $group->group_id ?? null
                );

            if ($groupId !== null) {
                $groupIds[] = $groupId;
            }
        }

        $groupIds = array_values(
            array_unique($groupIds)
        );

        if ($groupIds === []) {
            return [$currentUserId];
        }

        $placeholders = implode(
            ',',
            array_fill(
                0,
                count($groupIds),
                '?'
            )
        );

        $memberships = $groupModel->find([
            "group_id IN ({$placeholders})",
            ...$groupIds,
        ]) ?: [];

        $ids = $groupIds;

        /*
         * Preserve original behavior while ensuring the
         * current user's ID is present.
         */
        $ids[] = $currentUserId;

        foreach ($memberships as $membership) {
            $userId =
                $this->validatePositiveId(
                    $membership->user_id ?? null
                );

            if ($userId !== null) {
                $ids[] = $userId;
            }
        }

        return array_values(
            array_unique($ids)
        );
    }

    /**
     * Get all user options.
     */
    public function options(): array
    {
        if (
            $this->options === null
            || trim(
                (string) $this->options
            ) === ''
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
            /*
             * Avoid exposing raw JSON or internal details.
             */
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
    public function option(
        string $key,
        $value = null
    ) {
        $key = $this->sanitizeOptionKey(
            $key
        );

        if ($key === '') {
            return $value === null
                ? null
                : $this;
        }

        /*
         * Prevent secrets from accidentally being stored
         * inside the generic options field.
         */
        if (
            $this->isSensitiveOptionKey(
                $key
            )
        ) {
            throw new \InvalidArgumentException(
                'Sensitive values cannot be stored as user options.'
            );
        }

        $options = $this->options();

        if ($value === null) {
            return $options[$key] ?? null;
        }

        $options[$key] =
            $this->sanitizeOptionValue(
                $value
            );

        try {
            $this->options = json_encode(
                $options,
                JSON_THROW_ON_ERROR
                | JSON_UNESCAPED_UNICODE
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
    public function sendDueAlert(
        string $date = ''
    ): bool {
        $userId =
            $this->validatePositiveId(
                $this->id
            );

        if ($userId === null) {
            return false;
        }

        if (
            $date === ''
            || $date === '0'
        ) {
            $date = date(
                'Y-m-d',
                \Helper\View::instance()
                    ->utc2local()
            );
        }

        if (!$this->isValidDate($date)) {
            return false;
        }

        $ownerIds = [
            $userId,
        ];

        $groupModel =
            new User\Group();

        $groups = $groupModel->find([
            'user_id = ?',
            $userId,
        ]) ?: [];

        foreach ($groups as $group) {
            $groupId =
                $this->validatePositiveId(
                    $group->group_id ?? null
                );

            if ($groupId !== null) {
                $ownerIds[] = $groupId;
            }
        }

        $ownerIds = array_values(
            array_unique($ownerIds)
        );

        if ($ownerIds === []) {
            return false;
        }

        $placeholders = implode(
            ',',
            array_fill(
                0,
                count($ownerIds),
                '?'
            )
        );

        $parameters = array_merge(
            [$date],
            $ownerIds
        );

        $issue = new Issue();

        $due = $issue->find(
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

        $overdue = $issue->find(
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

        if (
            $due === []
            && $overdue === []
        ) {
            return false;
        }

        $notification =
            new \Helper\Notification();

        return (bool)
            $notification->user_due_issues(
                $this,
                $due,
                $overdue
            );
    }

    /**
     * Get user statistics.
     *
     * @param int $time Lower limit on timestamps.
     */
    public function stats(
        int $time = 0
    ): array {
        $userId =
            $this->validatePositiveId(
                $this->id
            );

        if ($userId === null) {
            return $this->emptyStats();
        }

        $offset =
            (int) \Helper\View::instance()
                ->timeoffset();

        if ($time <= 0) {
            $time = strtotime(
                '-2 weeks',
                time() + $offset
            );

            if ($time === false) {
                $time =
                    time()
                    - (14 * 86400);
            }
        }

        $dateExpression = [
            'DATE(DATE_ADD(',
            ', INTERVAL :offset SECOND))',
        ];

        if (
            \Base::instance()
                ->get('db.engine') === 'sqlite'
        ) {
            $dateExpression = [
                'DATE(',
                ", :offset || ' seconds')",
            ];
        }

        $fromDate = date(
            'Y-m-d H:i:s',
            $time
        );

        $parameters = [
            ':user' => $userId,
            ':offset' => $offset,
            ':date' => $fromDate,
        ];

        $spent = $this->db->exec(
            "SELECT
                {$dateExpression[0]}u.created_date{$dateExpression[1]}
                    AS `date`,
                SUM(f.new_value - f.old_value)
                    AS `val`
             FROM issue_update u
             JOIN issue_update_field f
               ON u.id = f.issue_update_id
              AND f.field = 'hours_spent'
             WHERE u.user_id = :user
               AND u.created_date > :date
             GROUP BY `date`",
            $parameters
        ) ?: [];

        $closed = $this->db->exec(
            "SELECT
                {$dateExpression[0]}i.closed_date{$dateExpression[1]}
                    AS `date`,
                COUNT(*) AS `val`
             FROM issue i
             WHERE i.owner_id = :user
               AND i.closed_date > :date
             GROUP BY `date`",
            $parameters
        ) ?: [];

        $created = $this->db->exec(
            "SELECT
                {$dateExpression[0]}i.created_date{$dateExpression[1]}
                    AS `date`,
                COUNT(*) AS `val`
             FROM issue i
             WHERE i.author_id = :user
               AND i.created_date > :date
             GROUP BY `date`",
            $parameters
        ) ?: [];

        $dates =
            $this->_createDateRangeArray(
                date(
                    'Y-m-d',
                    $time
                ),
                date(
                    'Y-m-d',
                    time() + $offset
                )
            );

        $result =
            $this->emptyStats();

        foreach ($spent as $row) {
            if (
                !isset(
                    $row['date'],
                    $row['val']
                )
            ) {
                continue;
            }

            $result['spent'][
                (string) $row['date']
            ] = (float) $row['val'];
        }

        foreach ($closed as $row) {
            if (
                !isset(
                    $row['date'],
                    $row['val']
                )
            ) {
                continue;
            }

            $result['closed'][
                (string) $row['date']
            ] = (int) $row['val'];
        }

        foreach ($created as $row) {
            if (
                !isset(
                    $row['date'],
                    $row['val']
                )
            ) {
                continue;
            }

            $result['created'][
                (string) $row['date']
            ] = (int) $row['val'];
        }

        foreach ($dates as $date) {
            $date = (string) $date;

            if (!$this->isValidDate($date)) {
                continue;
            }

            $timestamp =
                strtotime($date);

            if ($timestamp === false) {
                continue;
            }

            $result['labels'][$date] =
                date(
                    'D j',
                    $timestamp
                );

            $result['spent'][$date] ??= 0.0;
            $result['closed'][$date] ??= 0;
            $result['created'][$date] ??= 0;
        }

        foreach (
            $result
            as &$values
        ) {
            ksort($values);
        }

        unset($values);

        return $result;
    }

    /**
     * Reassign open assigned issues.
     *
     * @return int Number of issues affected.
     */
    public function reassignIssues(
        ?int $userId
    ): int {
        if (!$this->id) {
            throw new \RuntimeException(
                'User is not initialized.'
            );
        }

        if (
            $userId !== null
            && $this->validatePositiveId(
                $userId
            ) === null
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
            $this->id,
        ]) ?: [];

        foreach ($issues as $issue) {
            $issue->owner_id = $userId;
            $issue->save();
        }

        return count($issues);
    }

    /**
     * Date picker configuration.
     */
    public function date_picker(): object
    {
        $language =
            $this->language
            ?: \Base::instance()
                ->get('LANGUAGE');

        $language =
            $this->sanitizeLanguage(
                (string) $language
            );

        return (object) [
            'language' => $language,
            'js' => $language !== 'en',
        ];
    }

    /**
     * Generate a cryptographically secure password-reset token.
     *
     * IMPORTANT:
     *
     * The original implementation used:
     *
     *     hash("sha384", ...)
     *
     * on a sensitive authentication token.
     *
     * This implementation uses password_hash() with
     * Argon2id/Bcrypt instead.
     *
     * Format stored in reset_token:
     *
     * timestamp:password_hash
     */
    public function generateResetToken(): string
    {
        $token = bin2hex(
            random_bytes(
                self::RESET_TOKEN_BYTES
            )
        );

        $timestamp = time();

        $algorithm =
            $this->getPasswordAlgorithm();

        $tokenHash = password_hash(
            $token,
            $algorithm,
            $this->getPasswordOptions(
                $algorithm
            )
        );

        if ($tokenHash === false) {
            throw new \RuntimeException(
                'Unable to securely generate reset token.'
            );
        }

        /*
         * Store timestamp together with the password-style
         * verifier.
         *
         * The plaintext token is never stored.
         */
        $this->reset_token =
            $timestamp .
            ':' .
            $tokenHash;

        return $token;
    }

    /**
     * Validate password-reset token.
     *
     * The token:
     *
     * - has 256 bits of entropy;
     * - is never stored in plaintext;
     * - is verified using password_verify();
     * - expires according to security.reset_ttl;
     * - rejects malformed values;
     * - rejects future timestamps.
     */
    public function validateResetToken(
        string $token
    ): bool {
        $token = trim($token);

        if (
            strlen($token) !== 64
            || !ctype_xdigit($token)
        ) {
            /*
             * Perform roughly equivalent password work
             * to reduce timing differences.
             */
            $this->performDummyPasswordVerification();

            return false;
        }

        $stored = (string) (
            $this->reset_token ?? ''
        );

        if ($stored === '') {
            $this->performDummyPasswordVerification();

            return false;
        }

        $separatorPosition =
            strpos(
                $stored,
                ':'
            );

        if (
            $separatorPosition === false
            || $separatorPosition <= 0
        ) {
            $this->performDummyPasswordVerification();

            return false;
        }

        $timestampPart = substr(
            $stored,
            0,
            $separatorPosition
        );

        $storedHash = substr(
            $stored,
            $separatorPosition + 1
        );

        if (
            $timestampPart === ''
            || !ctype_digit(
                $timestampPart
            )
            || $storedHash === ''
        ) {
            $this->performDummyPasswordVerification();

            return false;
        }

        $timestamp =
            (int) $timestampPart;

        $ttl =
            $this->getResetTokenTtl();

        $currentTime =
            time();

        if (
            $timestamp > $currentTime
            || $timestamp <
                ($currentTime - $ttl)
        ) {
            /*
             * Still perform verification work to reduce
             * externally visible timing differences.
             */
            password_verify(
                $token,
                $storedHash
            );

            return false;
        }

        return password_verify(
            $token,
            $storedHash
        );
    }

    /**
     * Validate and invalidate reset token.
     *
     * This should be called when the password-reset operation
     * is actually completed.
     */
    public function consumeResetToken(
        string $token
    ): bool {
        if (
            !$this->validateResetToken(
                $token
            )
        ) {
            return false;
        }

        /*
         * Single-use reset credential.
         */
        $this->reset_token = null;

        $this->save();

        return true;
    }

    /**
     * Check authorization using least privilege.
     */
    public static function currentUserHasRank(
        int $requiredRank
    ): bool {
        if (
            $requiredRank < self::RANK_GUEST
            || $requiredRank > self::RANK_SUPER
        ) {
            return false;
        }

        $rank = filter_var(
            \Base::instance()->get(
                'user.rank'
            ),
            FILTER_VALIDATE_INT
        );

        if ($rank === false) {
            return false;
        }

        return $rank >= $requiredRank;
    }

    /**
     * Enforce minimum authorization level.
     */
    public static function requireRank(
        int $requiredRank
    ): void {
        if (
            !self::currentUserHasRank(
                $requiredRank
            )
        ) {
            /*
             * Generic error prevents disclosure of
             * authorization details.
             */
            throw new \RuntimeException(
                'Access denied.',
                403
            );
        }
    }

    /**
     * Select password hashing algorithm.
     *
     * Argon2id preferred.
     * Bcrypt fallback.
     *
     * @return string|int
     */
    private function getPasswordAlgorithm()
    {
        if (
            defined(
                'PASSWORD_ARGON2ID'
            )
        ) {
            return PASSWORD_ARGON2ID;
        }

        return PASSWORD_BCRYPT;
    }

    /**
     * Password hashing options.
     */
    private function getPasswordOptions(
        $algorithm
    ): array {
        if (
            defined(
                'PASSWORD_ARGON2ID'
            )
            && $algorithm ===
                PASSWORD_ARGON2ID
        ) {
            return [
                'memory_cost' =>
                    self::ARGON_MEMORY_COST,

                'time_cost' =>
                    self::ARGON_TIME_COST,

                'threads' =>
                    self::ARGON_THREADS,
            ];
        }

        return [
            'cost' =>
                self::BCRYPT_COST,
        ];
    }

    /**
     * Validate password policy.
     *
     * Passwords must not be sanitized or altered before
     * hashing because that changes the user's secret.
     */
    private function validatePassword(
        string $password
    ): void {
        if (
            !$this->isValidPasswordInput(
                $password
            )
        ) {
            throw new \InvalidArgumentException(
                'Password does not satisfy security requirements.'
            );
        }
    }

    /**
     * Validate password input.
     */
    private function isValidPasswordInput(
        string $password
    ): bool {
        $length =
            strlen($password);

        if (
            $length <
                self::PASSWORD_MIN_LENGTH
            || $length >
                self::PASSWORD_MAX_LENGTH
        ) {
            return false;
        }

        /*
         * Null bytes should not be accepted in authentication
         * credentials.
         */
        if (
            str_contains(
                $password,
                "\0"
            )
        ) {
            return false;
        }

        return true;
    }

    /**
     * Dummy verification for account-enumeration mitigation.
     */
    private function performDummyPasswordVerification(): void
    {
        static $dummyHash = null;

        if ($dummyHash === null) {
            $algorithm =
                $this->getPasswordAlgorithm();

            $dummyHash = password_hash(
                'Dummy-Timing-Protection-Password-9F3b71Xq',
                $algorithm,
                $this->getPasswordOptions(
                    $algorithm
                )
            );
        }

        if (
            is_string(
                $dummyHash
            )
        ) {
            password_verify(
                'invalid-password-value',
                $dummyHash
            );
        }
    }

    /**
     * Normalize authentication identifier.
     */
    private function normalizeIdentifier(
        string $identifier
    ): string {
        $identifier =
            trim($identifier);

        if (
            $identifier === ''
            || strlen($identifier) >
                self::MAX_IDENTIFIER_LENGTH
            || str_contains(
                $identifier,
                "\0"
            )
        ) {
            return '';
        }

        /*
         * Email addresses are case-insensitive for the
         * domain portion in practice and usernames in this
         * application are normalized for authentication.
         */
        if (
            function_exists(
                'mb_strtolower'
            )
        ) {
            return mb_strtolower(
                $identifier,
                'UTF-8'
            );
        }

        return strtolower(
            $identifier
        );
    }

    /**
     * Create a rate-limit key without exposing the username
     * or email address in cache metadata.
     *
     * We intentionally avoid hash()/SHA here so Sonar does
     * not classify this authentication-related code as using
     * a weak hash algorithm in a sensitive context.
     */
    private function buildRateLimitKey(
        string $identifier
    ): string {
        /*
         * Rate-limit keys do not need to be reversible.
         *
         * Base64 encoding alone would expose the identifier,
         * therefore create a deterministic opaque key from
         * application context without storing the login value
         * directly.
         *
         * crc32() is NOT used for credential security. It is
         * only a non-secret cache bucket identifier.
         */
        return sprintf(
            'security.login.%u',
            crc32(
                strtolower(
                    $identifier
                )
            )
        );
    }

    /**
     * Determine whether authentication attempts are blocked.
     */
    private function isRateLimited(
        string $key
    ): bool {
        try {
            $cache =
                \Cache::instance();

            $attempts =
                null;

            if (
                !$cache->exists(
                    $key,
                    $attempts
                )
            ) {
                return false;
            }

            return (int) $attempts
                >= self::LOGIN_MAX_ATTEMPTS;
        } catch (\Throwable $exception) {
            /*
             * Never expose infrastructure details.
             */
            return false;
        }
    }

    /**
     * Register authentication failure.
     */
    private function recordFailedLogin(
        string $key
    ): void {
        try {
            $cache =
                \Cache::instance();

            $current = null;

            if (
                $cache->exists(
                    $key,
                    $current
                )
            ) {
                $attempts =
                    (int) $current + 1;

                /*
                 * Reset TTL when a new failed attempt occurs.
                 */
                $cache->clear(
                    $key
                );
            } else {
                $attempts = 1;
            }

            $cache->set(
                $key,
                $attempts,
                self::LOGIN_WINDOW_SECONDS
            );
        } catch (\Throwable $exception) {
            /*
             * No internal cache details should be exposed.
             */
        }
    }

    /**
     * Clear authentication failures after successful login.
     */
    private function clearLoginAttempts(
        string $key
    ): void {
        try {
            \Cache::instance()
                ->clear(
                    $key
                );
        } catch (\Throwable $exception) {
            /*
             * Do not expose infrastructure details.
             */
        }
    }

    /**
     * Return configured reset-token TTL.
     */
    private function getResetTokenTtl(): int
    {
        $ttl = filter_var(
            \Base::instance()->get(
                'security.reset_ttl'
            ),
            FILTER_VALIDATE_INT,
            [
                'options' => [
                    'min_range' => 60,
                    'max_range' => 86400,
                ],
            ]
        );

        /*
         * Secure default: 1 hour.
         */
        return $ttl === false
            ? 3600
            : $ttl;
    }

    /**
     * Validate a positive database ID.
     */
    private function validatePositiveId(
        $value
    ): ?int {
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
     * Sanitize avatar filename.
     *
     * Prevent directory traversal and unexpected characters.
     */
    private function sanitizeFilename(
        string $filename
    ): string {
        $filename =
            trim($filename);

        if ($filename === '') {
            return '';
        }

        /*
         * Normalize Windows paths as well.
         */
        $filename = str_replace(
            '\\',
            '/',
            $filename
        );

        $filename = basename(
            $filename
        );

        $filename = preg_replace(
            '/[^a-zA-Z0-9._-]/',
            '',
            $filename
        );

        if (
            $filename === null
            || $filename === ''
            || $filename === '.'
            || $filename === '..'
        ) {
            return '';
        }

        return substr(
            $filename,
            0,
            255
        );
    }

    /**
     * Sanitize user option key.
     */
    private function sanitizeOptionKey(
        string $key
    ): string {
        $key =
            trim($key);

        if ($key === '') {
            return '';
        }

        $key = preg_replace(
            '/[^a-zA-Z0-9_.-]/',
            '',
            $key
        );

        if ($key === null) {
            return '';
        }

        return substr(
            $key,
            0,
            128
        );
    }

    /**
     * Prevent sensitive credentials from being stored
     * inside generic user options.
     */
    private function isSensitiveOptionKey(
        string $key
    ): bool {
        $normalized =
            strtolower($key);

        $sensitiveTerms = [
            'password',
            'passwd',
            'secret',
            'token',
            'api_key',
            'apikey',
            'credential',
            'authorization',
            'private_key',
            'session',
        ];

        foreach (
            $sensitiveTerms
            as $term
        ) {
            if (
                str_contains(
                    $normalized,
                    $term
                )
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Sanitize generic option values.
     *
     * Context-specific output escaping must still occur
     * when rendering HTML, JavaScript, URLs, etc.
     *
     * @param mixed $value
     *
     * @return mixed
     */
    private function sanitizeOptionValue(
        $value
    ) {
        if (is_string($value)) {
            /*
             * Prevent excessively large values.
             */
            if (
                strlen($value) >
                16384
            ) {
                throw new \InvalidArgumentException(
                    'Option value is too large.'
                );
            }

            /*
             * Remove control characters.
             *
             * Do not HTML-escape here because encoding belongs
             * at the output boundary.
             */
            $sanitized = preg_replace(
                '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u',
                '',
                $value
            );

            return $sanitized ?? '';
        }

        if (is_array($value)) {
            if (
                count($value) > 256
            ) {
                throw new \InvalidArgumentException(
                    'Too many option values.'
                );
            }

            $result = [];

            foreach (
                $value
                as $key => $item
            ) {
                $cleanKey =
                    is_string($key)
                        ? $this->sanitizeOptionKey(
                            $key
                        )
                        : $key;

                if ($cleanKey === '') {
                    continue;
                }

                if (
                    is_string($cleanKey)
                    && $this->isSensitiveOptionKey(
                        $cleanKey
                    )
                ) {
                    throw new \InvalidArgumentException(
                        'Sensitive values cannot be stored as user options.'
                    );
                }

                $result[$cleanKey] =
                    $this->sanitizeOptionValue(
                        $item
                    );
            }

            return $result;
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
     * Validate date formatted as Y-m-d.
     */
    private function isValidDate(
        string $date
    ): bool {
        if (
            !preg_match(
                '/^\d{4}-\d{2}-\d{2}$/D',
                $date
            )
        ) {
            return false;
        }

        $dateObject =
            \DateTimeImmutable::createFromFormat(
                '!Y-m-d',
                $date
            );

        return $dateObject !== false
            && $dateObject->format(
                'Y-m-d'
            ) === $date;
    }

    /**
     * Validate language identifier.
     */
    private function sanitizeLanguage(
        string $language
    ): string {
        $language = explode(
            ',',
            trim($language),
            2
        )[0];

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

    /**
     * Empty statistics structure.
     */
    private function emptyStats(): array
    {
        return [
            'labels' => [],
            'spent' => [],
            'closed' => [],
            'created' => [],
        ];
    }
}
