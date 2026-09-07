<?php

declare(strict_types=1);

namespace Model;

/**
 * Class User
 *
 * Security focus: CONFIDENTIALITY
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
     * OWASP minimum Argon2id baseline:
     * 19 MiB memory, 2 iterations, parallelism 1.
     */
    private const ARGON_MEMORY_COST = 19456;
    private const ARGON_TIME_COST = 2;
    private const ARGON_THREADS = 1;

    private const RESET_TOKEN_RANDOM_BYTES = 32;
    private const RESET_TOKEN_HASH_ALGORITHM = 'sha384';
    private const RESET_TOKEN_HASH_LENGTH = 96;

    private const LOGIN_MAX_ATTEMPTS = 5;
    private const LOGIN_WINDOW_SECONDS = 900;

    private const RESET_MAX_ATTEMPTS = 5;
    private const RESET_WINDOW_SECONDS = 900;

    private const MAX_IDENTIFIER_LENGTH = 254;

    private const MAX_AVATAR_SIZE = 2048;

    protected $_table_name = 'user';

    protected $_groupUsers = null;

    /**
     * Load currently authenticated user.
     *
     * Sensitive information is deliberately excluded from
     * the globally accessible F3 user context.
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
         * CONFIDENTIALITY:
         *
         * Do NOT expose:
         * - password
         * - salt
         * - reset_token
         * - api_key
         *
         * through the globally available hive.
         */
        $f3->set(
            'user',
            $this->getPublicSessionData()
        );

        /*
         * Keep the object for compatibility with the project,
         * but sensitive information must never be serialized
         * or rendered from this object.
         */
        $f3->set('user_obj', $this);

        if ($this->exists('language') && $this->language) {
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
     * Return only information that is safe to place
     * in the application-wide authenticated-user context.
     */
    public function getPublicSessionData(): array
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
     * Securely hash and store a password.
     *
     * Argon2id is preferred. Bcrypt is used only as fallback.
     */
    public function setPassword(string $plainPassword): static
    {
        $this->validatePassword($plainPassword);

        $algorithm = $this->getPasswordAlgorithm();
        $options = $this->getPasswordOptions($algorithm);

        $hash = password_hash(
            $plainPassword,
            $algorithm,
            $options
        );

        if ($hash === false) {
            throw new \RuntimeException(
                'Unable to securely hash password.'
            );
        }

        $this->password = $hash;

        /*
         * password_hash() generates and stores its own salt.
         * A separate application-managed salt is unnecessary
         * and should not be reused.
         */
        $this->salt = null;

        return $this;
    }

    /**
     * Verify a plaintext password using PHP's timing-safe
     * password verification implementation.
     */
    public function verifyPassword(string $plainPassword): bool
    {
        if (!$this->isValidPasswordInput($plainPassword)) {
            /*
             * Run a dummy password operation to reduce observable
             * timing differences for malformed requests.
             */
            $this->dummyPasswordVerification();

            return false;
        }

        $storedHash = (string) ($this->password ?? '');

        if ($storedHash === '') {
            $this->dummyPasswordVerification();

            return false;
        }

        return password_verify(
            $plainPassword,
            $storedHash
        );
    }

    /**
     * Upgrade password hashes automatically when the current
     * algorithm or parameters become outdated.
     */
    public function rehashPasswordIfNecessary(
        string $plainPassword
    ): bool {
        if (!$this->verifyPassword($plainPassword)) {
            return false;
        }

        $algorithm = $this->getPasswordAlgorithm();
        $options = $this->getPasswordOptions($algorithm);

        if (
            password_needs_rehash(
                (string) $this->password,
                $algorithm,
                $options
            )
        ) {
            $this->setPassword($plainPassword);
            $this->save();
        }

        return true;
    }

    /**
     * Secure authentication entry point.
     *
     * Implements:
     * - generic authentication result;
     * - account enumeration resistance;
     * - brute-force protection;
     * - password verification;
     * - password hash migration;
     * - deleted account protection.
     *
     * $clientKey should ideally contain a trusted representation
     * of the remote client (for example the validated remote IP).
     */
    public function authenticateSecure(
        string $identifier,
        string $password,
        string $clientKey = ''
    ): bool {
        $identifier = $this->normalizeIdentifier($identifier);
        $clientKey = $this->normalizeClientKey($clientKey);

        if (
            $identifier === ''
            || !$this->isValidPasswordInput($password)
        ) {
            $this->dummyPasswordVerification();

            return false;
        }

        $rateLimitKey = $this->buildLoginRateLimitKey(
            $identifier,
            $clientKey
        );

        if ($this->isRateLimited($rateLimitKey)) {
            /*
             * Perform dummy work to avoid making lockout state
             * trivially distinguishable through timing.
             */
            $this->dummyPasswordVerification();

            return false;
        }

        $this->load([
            '(username = ? OR email = ?) AND deleted_date IS NULL',
            $identifier,
            $identifier,
        ]);

        if (!$this->id) {
            $this->dummyPasswordVerification();
            $this->recordFailedAttempt($rateLimitKey);

            return false;
        }

        if (!$this->verifyPassword($password)) {
            $this->recordFailedAttempt($rateLimitKey);

            return false;
        }

        /*
         * Authentication succeeded.
         */
        $this->clearFailedAttempts($rateLimitKey);

        /*
         * Seamlessly migrate Bcrypt/old Argon parameters
         * to the currently preferred configuration.
         */
        $this->rehashPasswordIfNecessary($password);

        return true;
    }

    /**
     * Verify an API key without using equality operators
     * on secret values.
     */
    public function verifyApiKey(string $providedApiKey): bool
    {
        $storedApiKey = (string) ($this->api_key ?? '');

        if (
            $providedApiKey === ''
            || $storedApiKey === ''
            || strlen($providedApiKey) > 512
        ) {
            return false;
        }

        /*
         * Compare hashes of fixed size to avoid leaking
         * information about secret length.
         */
        $expected = hash(
            'sha256',
            $storedApiKey
        );

        $provided = hash(
            'sha256',
            $providedApiKey
        );

        return hash_equals(
            $expected,
            $provided
        );
    }

    /**
     * Generate a cryptographically secure API key.
     *
     * The caller is responsible for displaying the returned
     * plaintext key only once.
     */
    public function generateApiKey(): string
    {
        $apiKey = bin2hex(
            random_bytes(32)
        );

        /*
         * Existing database schema stores api_key directly.
         *
         * Ideally the schema should store a SHA-256/HMAC hash
         * instead of the plaintext key. This assignment preserves
         * compatibility with the existing schema.
         */
        $this->api_key = $apiKey;

        return $apiKey;
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
            min(self::MAX_AVATAR_SIZE, $size)
        );

        $avatarFilename = $this->sanitizeFilename(
            (string) $this->get('avatar_filename')
        );

        if ($avatarFilename !== '') {
            $avatarPath =
                'uploads/avatars/' .
                $avatarFilename;

            if (is_file($avatarPath)) {
                return sprintf(
                    '%s/avatar/%d-%d.png',
                    rtrim(
                        (string) \Base::instance()->get('BASE'),
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

        return \Helper\View::instance()->gravatar(
            $email !== false ? $email : '',
            $size
        );
    }

    /**
     * Load active users.
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
     * Deleted-user information is more sensitive than the
     * normal user directory and requires administrative access.
     */
    public function getAllDeleted(): array
    {
        $this->requireMinimumRank(
            self::RANK_ADMIN
        );

        return $this->find(
            "deleted_date IS NOT NULL AND role != 'group'",
            [
                'order' => 'name ASC',
            ]
        ) ?: [];
    }

    /**
     * Load active groups.
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
     * Get users within a group.
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
     * Get user IDs within a group.
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
            $id = $this->validatePositiveId(
                $user->id ?? null
            );

            if ($id !== null) {
                $ids[] = $id;
            }
        }

        return array_values(
            array_unique($ids)
        );
    }

    /**
     * Get IDs of users sharing groups with this user.
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

        $memberships =
            $groupModel->find([
                "group_id IN ({$placeholders})",
                ...$groupIds,
            ]) ?: [];

        $ids = $groupIds;
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
     * Get or set an option.
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
         * Prevent secrets from accidentally being copied
         * into the generic options JSON field.
         */
        if ($this->isSensitiveOptionKey($key)) {
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
     * Send due issue alert.
     */
    public function sendDueAlert(
        string $date = ''
    ): bool {
        $userId = $this->validatePositiveId(
            $this->id
        );

        if ($userId === null) {
            return false;
        }

        if ($date === '' || $date === '0') {
            $date = date(
                'Y-m-d',
                \Helper\View::instance()
                    ->utc2local()
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
                    time() - (14 * 86400);
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

        $fromDate =
            date('Y-m-d H:i:s', $time);

        $parameters = [
            ':user' => $userId,
            ':offset' => $offset,
            ':date' => $fromDate,
        ];

        $spent = $this->db->exec(
            "SELECT
                {$dateExpression[0]}
                u.created_date
                {$dateExpression[1]} AS `date`,
                SUM(f.new_value - f.old_value) AS `val`
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
                {$dateExpression[0]}
                i.closed_date
                {$dateExpression[1]} AS `date`,
                COUNT(*) AS `val`
             FROM issue i
             WHERE i.owner_id = :user
               AND i.closed_date > :date
             GROUP BY `date`",
            $parameters
        ) ?: [];

        $created = $this->db->exec(
            "SELECT
                {$dateExpression[0]}
                i.created_date
                {$dateExpression[1]} AS `date`,
                COUNT(*) AS `val`
             FROM issue i
             WHERE i.author_id = :user
               AND i.created_date > :date
             GROUP BY `date`",
            $parameters
        ) ?: [];

        $dates =
            $this->_createDateRangeArray(
                date('Y-m-d', $time),
                date(
                    'Y-m-d',
                    time() + $offset
                )
            );

        $result = $this->emptyStats();

        foreach ($spent as $row) {
            if (
                isset(
                    $row['date'],
                    $row['val']
                )
            ) {
                $result['spent'][
                    (string) $row['date']
                ] = (float) $row['val'];
            }
        }

        foreach ($closed as $row) {
            if (
                isset(
                    $row['date'],
                    $row['val']
                )
            ) {
                $result['closed'][
                    (string) $row['date']
                ] = (int) $row['val'];
            }
        }

        foreach ($created as $row) {
            if (
                isset(
                    $row['date'],
                    $row['val']
                )
            ) {
                $result['created'][
                    (string) $row['date']
                ] = (int) $row['val'];
            }
        }

        foreach ($dates as $date) {
            $date = (string) $date;

            if (!$this->isValidDate($date)) {
                continue;
            }

            $timestamp = strtotime($date);

            if ($timestamp === false) {
                continue;
            }

            $result['labels'][$date] =
                date('D j', $timestamp);

            $result['spent'][$date] ??= 0.0;
            $result['closed'][$date] ??= 0;
            $result['created'][$date] ??= 0;
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
     * Administrative/manager operation.
     */
    public function reassignIssues(
        ?int $userId
    ): int {
        $this->requireMinimumRank(
            self::RANK_MANAGER
        );

        $currentUserId =
            $this->validatePositiveId(
                $this->id
            );

        if ($currentUserId === null) {
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
            $currentUserId,
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
     * Generate a password-reset token.
     *
     * Only the SHA-384 hash is stored in the database.
     */
    public function generateResetToken(): string
    {
        $random = bin2hex(
            random_bytes(
                self::RESET_TOKEN_RANDOM_BYTES
            )
        );

        $timestamp = (string) time();

        $token =
            $random .
            '.' .
            $timestamp;

        $this->reset_token = hash(
            self::RESET_TOKEN_HASH_ALGORITHM,
            $token
        );

        return $token;
    }

    /**
     * Validate password-reset token.
     *
     * Includes:
     * - strict input format;
     * - expiration;
     * - future timestamp rejection;
     * - timing-safe secret comparison;
     * - brute-force throttling.
     */
    public function validateResetToken(
        string $token
    ): bool {
        $token = trim($token);

        $userId =
            $this->validatePositiveId(
                $this->id
            );

        $rateLimitKey =
            $this->buildResetRateLimitKey(
                $userId ?? 0
            );

        if ($this->isRateLimited(
            $rateLimitKey,
            self::RESET_MAX_ATTEMPTS
        )) {
            return false;
        }

        if (
            $token === ''
            || strlen($token) > 256
            || empty($this->reset_token)
        ) {
            $this->recordFailedAttempt(
                $rateLimitKey,
                self::RESET_WINDOW_SECONDS
            );

            return false;
        }

        if (
            !preg_match(
                '/^[a-f0-9]{64}\.[0-9]{1,12}$/D',
                $token
            )
        ) {
            $this->recordFailedAttempt(
                $rateLimitKey,
                self::RESET_WINDOW_SECONDS
            );

            return false;
        }

        [$randomPart, $timestampPart] =
            explode('.', $token, 2);

        if (
            strlen($randomPart) !== 64
            || !ctype_xdigit($randomPart)
            || !ctype_digit($timestampPart)
        ) {
            $this->recordFailedAttempt(
                $rateLimitKey,
                self::RESET_WINDOW_SECONDS
            );

            return false;
        }

        $ttl = filter_var(
            \Base::instance()->get(
                'security.reset_ttl'
            ),
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

        $timestamp =
            (int) $timestampPart;

        $currentTime = time();

        if (
            $timestamp > $currentTime
            || $timestamp <
                ($currentTime - $ttl)
        ) {
            $this->recordFailedAttempt(
                $rateLimitKey,
                self::RESET_WINDOW_SECONDS
            );

            return false;
        }

        $storedHash =
            (string) $this->reset_token;

        if (
            strlen($storedHash)
                !==
                self::RESET_TOKEN_HASH_LENGTH
            || !ctype_xdigit($storedHash)
        ) {
            return false;
        }

        $providedHash = hash(
            self::RESET_TOKEN_HASH_ALGORITHM,
            $token
        );

        $valid = hash_equals(
            strtolower($storedHash),
            $providedHash
        );

        if (!$valid) {
            $this->recordFailedAttempt(
                $rateLimitKey,
                self::RESET_WINDOW_SECONDS
            );

            return false;
        }

        $this->clearFailedAttempts(
            $rateLimitKey
        );

        return true;
    }

    /**
     * Consume reset token once.
     *
     * Call this immediately after the token has been accepted
     * and before completing the password-reset workflow.
     */
    public function consumeResetToken(
        string $token
    ): bool {
        if (!$this->validateResetToken($token)) {
            return false;
        }

        /*
         * Single-use token.
         */
        $this->reset_token = null;

        $this->save();

        return true;
    }

    /**
     * Check current user privilege using least privilege.
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

        $rank = \Base::instance()->get(
            'user.rank'
        );

        $validatedRank = filter_var(
            $rank,
            FILTER_VALIDATE_INT
        );

        if ($validatedRank === false) {
            return false;
        }

        return $validatedRank >= $requiredRank;
    }

    /**
     * Enforce least privilege.
     */
    private function requireMinimumRank(
        int $requiredRank
    ): void {
        if (
            !self::currentUserHasRank(
                $requiredRank
            )
        ) {
            /*
             * Do not reveal which permission or resource
             * caused the authorization failure.
             */
            throw new \RuntimeException(
                'Access denied.',
                403
            );
        }
    }

    /**
     * Select password hashing algorithm.
     */
    private function getPasswordAlgorithm()
    {
        if (
            defined('PASSWORD_ARGON2ID')
        ) {
            return PASSWORD_ARGON2ID;
        }

        return PASSWORD_BCRYPT;
    }

    /**
     * Password hashing parameters.
     */
    private function getPasswordOptions(
        $algorithm
    ): array {
        if (
            defined('PASSWORD_ARGON2ID')
            && $algorithm === PASSWORD_ARGON2ID
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
            'cost' => self::BCRYPT_COST,
        ];
    }

    /**
     * Password policy.
     *
     * Passwords are validated, not "sanitized":
     * modifying passwords would change the user's secret.
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

    private function isValidPasswordInput(
        string $password
    ): bool {
        $length = strlen($password);

        if (
            $length
                < self::PASSWORD_MIN_LENGTH
            || $length
                > self::PASSWORD_MAX_LENGTH
        ) {
            return false;
        }

        /*
         * Protect affected/legacy PHP environments and
         * reject binary null characters in secrets.
         */
        if (str_contains($password, "\0")) {
            return false;
        }

        return true;
    }

    /**
     * Dummy password verification used to reduce user
     * enumeration through timing differences.
     */
    private function dummyPasswordVerification(): void
    {
        static $dummyHash = null;

        if ($dummyHash === null) {
            $algorithm =
                $this->getPasswordAlgorithm();

            $dummyHash = password_hash(
                'DummyPassword-Only-For-Timing-Protection-9f4b1',
                $algorithm,
                $this->getPasswordOptions(
                    $algorithm
                )
            );
        }

        if (is_string($dummyHash)) {
            password_verify(
                'InvalidPasswordValue',
                $dummyHash
            );
        }
    }

    /**
     * Normalize login identifier without altering
     * legitimate password data.
     */
    private function normalizeIdentifier(
        string $identifier
    ): string {
        $identifier = trim($identifier);

        if (
            $identifier === ''
            || strlen($identifier)
                > self::MAX_IDENTIFIER_LENGTH
            || str_contains(
                $identifier,
                "\0"
            )
        ) {
            return '';
        }

        return mb_strtolower(
            $identifier,
            'UTF-8'
        );
    }

    private function normalizeClientKey(
        string $clientKey
    ): string {
        $clientKey = trim($clientKey);

        if (
            $clientKey === ''
            || strlen($clientKey) > 128
        ) {
            return 'unknown';
        }

        return hash(
            'sha256',
            $clientKey
        );
    }

    /**
     * Build a rate-limit key without storing usernames,
     * emails or IP addresses in plaintext cache keys.
     */
    private function buildLoginRateLimitKey(
        string $identifier,
        string $clientKey
    ): string {
        return 'security.login.' . hash(
            'sha256',
            $identifier .
            '|' .
            $clientKey
        );
    }

    private function buildResetRateLimitKey(
        int $userId
    ): string {
        return 'security.reset.' . hash(
            'sha256',
            (string) $userId
        );
    }

    /**
     * Server-side brute-force rate limiting.
     *
     * Fat-Free's cache must be enabled for persistence
     * across requests.
     */
    private function isRateLimited(
        string $key,
        int $maximum =
            self::LOGIN_MAX_ATTEMPTS
    ): bool {
        try {
            $cache = \Cache::instance();

            $value = null;

            if (!$cache->exists(
                $key,
                $value
            )) {
                return false;
            }

            return (int) $value >= $maximum;
        } catch (\Throwable $exception) {
            /*
             * Authentication must not expose cache details.
             */
            return false;
        }
    }

    private function recordFailedAttempt(
        string $key,
        int $ttl =
            self::LOGIN_WINDOW_SECONDS
    ): void {
        try {
            $cache = \Cache::instance();

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
                 * Clear first because Fat-Free retains
                 * an existing cache entry's expiration.
                 */
                $cache->clear($key);
            } else {
                $attempts = 1;
            }

            $cache->set(
                $key,
                $attempts,
                $ttl
            );
        } catch (\Throwable $exception) {
            /*
             * Do not leak infrastructure/cache failures.
             */
        }
    }

    private function clearFailedAttempts(
        string $key
    ): void {
        try {
            \Cache::instance()
                ->clear($key);
        } catch (\Throwable $exception) {
            /*
             * Avoid exposing infrastructure details.
             */
        }
    }

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

    private function sanitizeFilename(
        string $filename
    ): string {
        $filename = trim($filename);

        if ($filename === '') {
            return '';
        }

        $filename = basename(
            str_replace(
                '\\',
                '/',
                $filename
            )
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

    private function sanitizeOptionKey(
        string $key
    ): string {
        $key = trim($key);

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

    private function isSensitiveOptionKey(
        string $key
    ): bool {
        $normalized =
            strtolower($key);

        $sensitivePatterns = [
            'password',
            'passwd',
            'secret',
            'token',
            'api_key',
            'apikey',
            'private_key',
            'credential',
            'authorization',
        ];

        foreach (
            $sensitivePatterns
            as $pattern
        ) {
            if (
                str_contains(
                    $normalized,
                    $pattern
                )
            ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Sanitize generic preference data.
     *
     * Output encoding must still be performed
     * at the rendering context.
     *
     * @param mixed $value
     *
     * @return mixed
     */
    private function sanitizeOptionValue(
        $value
    ) {
        if (is_string($value)) {
            if (strlen($value) > 16384) {
                throw new \InvalidArgumentException(
                    'Option value is too large.'
                );
            }

            $value = preg_replace(
                '/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u',
                '',
                $value
            );

            return $value ?? '';
        }

        if (is_array($value)) {
            if (count($value) > 256) {
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

    private function sanitizeLanguage(
        string $language
    ): string {
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

        $object =
            \DateTimeImmutable::createFromFormat(
                '!Y-m-d',
                $date
            );

        return $object !== false
            && $object->format('Y-m-d')
                === $date;
    }

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

