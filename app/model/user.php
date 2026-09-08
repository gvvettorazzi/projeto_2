<?php

namespace Model;

class User extends \Model
{
    public const RANK_GUEST = 0;
    public const RANK_CLIENT = 1;
    public const RANK_USER = 2;
    public const RANK_MANAGER = 3;
    public const RANK_ADMIN = 4;
    public const RANK_SUPER = 5;

    private const ARGON_MEMORY_COST = 19456;
    private const ARGON_TIME_COST = 2;
    private const ARGON_THREADS = 1;

    private const BCRYPT_COST = 12;

    private const PASSWORD_MAX_LENGTH = 1024;
    private const RESET_TOKEN_BYTES = 32;

    protected $_table_name = 'user';
    protected $_groupUsers;

    /**
     * Load currently authenticated user.
     */
    public function loadCurrent(): static
    {
        $f3 = \Base::instance();

        $session = new Session();
        $session->loadCurrent();

        $userId = filter_var(
            $session->user_id,
            FILTER_VALIDATE_INT,
            [
                'options' => [
                    'min_range' => 1,
                ],
            ]
        );

        if ($userId === false) {
            $this->clearCurrentUser();
            return $this;
        }

        $this->load([
            'id = ? AND deleted_date IS NULL',
            $userId,
        ]);

        if (!$this->id) {
            $session->delete();
            $this->clearCurrentUser();

            return $this;
        }

        $f3->set(
            'user',
            $this->safeSessionData()
        );

        $f3->set(
            'user_obj',
            $this
        );

        if (
            $this->exists('language')
            && is_string($this->language)
            && $this->language !== ''
        ) {
            $f3->set(
                'LANGUAGE',
                $this->language
            );
        }

        return $this;
    }

    /**
     * Remove user information from application state.
     */
    private function clearCurrentUser(): void
    {
        $f3 = \Base::instance();

        $f3->clear('user');
        $f3->clear('user_obj');
    }

    /**
     * User data that may safely be exposed to application views.
     */
    public function safeSessionData(): array
    {
        $data = $this->cast();

        unset(
            $data['password'],
            $data['salt'],
            $data['reset_token'],
            $data['api_key']
        );

        return $data;
    }

    /**
     * Store password using Argon2id when available,
     * otherwise Bcrypt.
     */
    public function setPassword(string $password): static
    {
        $password = $this->validatePasswordInput(
            $password
        );

        $hash = $this->hashPassword(
            $password
        );

        if ($hash === null) {
            throw new \RuntimeException(
                'Unable to securely hash password.'
            );
        }

        $this->password = $hash;

        /*
         * Legacy salt is no longer needed when using
         * password_hash().
         */
        $this->salt = null;

        return $this;
    }

    /**
     * Verify password using PHP's constant-time password API.
     */
    public function verifyPassword(
        string $password
    ): bool {
        if (
            !$this->id
            || $this->deleted_date
            || !is_string($this->password)
            || $this->password === ''
        ) {
            self::dummyPasswordVerify(
                $password
            );

            return false;
        }

        if (
            $password === ''
            || strlen($password)
                > self::PASSWORD_MAX_LENGTH
        ) {
            self::dummyPasswordVerify(
                $password
            );

            return false;
        }

        $valid = password_verify(
            $password,
            $this->password
        );

        if (!$valid) {
            return false;
        }

        if (
            $this->passwordNeedsRehash(
                $this->password
            )
        ) {
            $newHash =
                $this->hashPassword(
                    $password
                );

            if ($newHash !== null) {
                $this->password = $newHash;
                $this->salt = null;

                /*
                 * Saving without notifications.
                 */
                parent::save();
            }
        }

        return true;
    }

    /**
     * Create modern password hash.
     */
    private function hashPassword(
        string $password
    ): ?string {
        if (defined('PASSWORD_ARGON2ID')) {
            $hash = password_hash(
                $password,
                PASSWORD_ARGON2ID,
                [
                    'memory_cost' =>
                        self::ARGON_MEMORY_COST,

                    'time_cost' =>
                        self::ARGON_TIME_COST,

                    'threads' =>
                        self::ARGON_THREADS,
                ]
            );
        } else {
            /*
             * Bcrypt uses only the first 72 bytes.
             * Reject oversized values rather than silently
             * truncating them.
             */
            if (strlen($password) > 72) {
                throw new \InvalidArgumentException(
                    'Password is too long for Bcrypt.'
                );
            }

            $hash = password_hash(
                $password,
                PASSWORD_BCRYPT,
                [
                    'cost' =>
                        self::BCRYPT_COST,
                ]
            );
        }

        return is_string($hash)
            ? $hash
            : null;
    }

    private function passwordNeedsRehash(
        string $hash
    ): bool {
        if (defined('PASSWORD_ARGON2ID')) {
            return password_needs_rehash(
                $hash,
                PASSWORD_ARGON2ID,
                [
                    'memory_cost' =>
                        self::ARGON_MEMORY_COST,

                    'time_cost' =>
                        self::ARGON_TIME_COST,

                    'threads' =>
                        self::ARGON_THREADS,
                ]
            );
        }

        return password_needs_rehash(
            $hash,
            PASSWORD_BCRYPT,
            [
                'cost' =>
                    self::BCRYPT_COST,
            ]
        );
    }

    private function validatePasswordInput(
        string $password
    ): string {
        $length = strlen($password);

        if (
            $length === 0
            || $length
                > self::PASSWORD_MAX_LENGTH
        ) {
            throw new \InvalidArgumentException(
                'Invalid password length.'
            );
        }

        $minimum =
            (int) \Base::instance()
                ->get(
                    'security.min_pass_len'
                );

        if ($minimum < 8) {
            $minimum = 8;
        }

        if ($length < $minimum) {
            throw new \InvalidArgumentException(
                'Password is too short.'
            );
        }

        return $password;
    }

    /**
     * Performs approximately the same expensive password
     * operation for unknown users.
     *
     * Helps reduce account enumeration via timing.
     */
    private static function dummyPasswordVerify(
        string $password
    ): void {
        static $dummyHash = null;

        if ($dummyHash === null) {
            $dummyHash = password_hash(
                'dummy-authentication-password',
                PASSWORD_BCRYPT,
                [
                    'cost' => 10,
                ]
            );
        }

        if (is_string($dummyHash)) {
            password_verify(
                $password,
                $dummyHash
            );
        }
    }

    /**
     * Compare arbitrary secrets without early-exit comparison.
     */
    public static function secretsEqual(
        string $expected,
        string $provided
    ): bool {
        return hash_equals(
            hash('sha256', $expected),
            hash('sha256', $provided)
        );
    }

    /**
     * Verify API key without normal string comparison.
     */
    public function verifyApiKey(
        string $provided
    ): bool {
        if (
            !$this->id
            || $this->deleted_date
            || !is_string($this->api_key)
            || $this->api_key === ''
            || $provided === ''
        ) {
            return false;
        }

        return self::secretsEqual(
            $this->api_key,
            $provided
        );
    }

    /**
     * Generate cryptographically random API key.
     *
     * Ideally migrate the database later to store only
     * a hash of this value.
     */
    public function generateApiKey(): string
    {
        $key = bin2hex(
            random_bytes(32)
        );

        $this->api_key = $key;

        return $key;
    }

    /**
     * Create reset token.
     *
     * Plain token is returned to the caller.
     * Only a SHA-256 verifier is stored.
     */
    public function generateResetToken(): string
    {
        $random =
            bin2hex(
                random_bytes(
                    self::RESET_TOKEN_BYTES
                )
            );

        $timestamp = time();

        $token =
            $random
            . '.'
            . $timestamp;

        $this->reset_token =
            hash(
                'sha256',
                $token
            );

        return $token;
    }

    /**
     * Validate reset token with TTL and timing-safe
     * comparison.
     */
    public function validateResetToken(
        string $token
    ): bool {
        if (
            !is_string($this->reset_token)
            || $this->reset_token === ''
        ) {
            return false;
        }

        if (
            preg_match(
                '/\A([a-f0-9]{64})\.([0-9]{1,10})\z/D',
                $token,
                $matches
            ) !== 1
        ) {
            return false;
        }

        $timestamp =
            filter_var(
                $matches[2],
                FILTER_VALIDATE_INT
            );

        if ($timestamp === false) {
            return false;
        }

        $ttl =
            (int) \Base::instance()
                ->get(
                    'security.reset_ttl'
                );

        if ($ttl <= 0) {
            $ttl = 3600;
        }

        $now = time();

        /*
         * Reject expired tokens and tokens from an
         * implausible future timestamp.
         */
        if (
            $timestamp
                < ($now - $ttl)
            || $timestamp
                > ($now + 60)
        ) {
            return false;
        }

        $calculated =
            hash(
                'sha256',
                $token
            );

        return hash_equals(
            $this->reset_token,
            $calculated
        );
    }

    public function invalidateResetToken(): static
    {
        $this->reset_token = null;

        return $this;
    }

    /**
     * Least-privilege helper.
     */
    public function hasMinimumRank(
        int $requiredRank
    ): bool {
        if (
            !$this->id
            || $this->deleted_date
        ) {
            return false;
        }

        if (
            $requiredRank < self::RANK_GUEST
            || $requiredRank > self::RANK_SUPER
        ) {
            return false;
        }

        return (int) $this->rank
            >= $requiredRank;
    }

    public function avatar(int $size = 80)
    {
        if (!$this->id) {
            return false;
        }

        $size = max(
            16,
            min($size, 512)
        );

        $filename =
            $this->get(
                'avatar_filename'
            );

        if (
            is_string($filename)
            && preg_match(
                '/\A[a-zA-Z0-9._-]+\z/D',
                $filename
            ) === 1
        ) {
            $path =
                'uploads/avatars/'
                . basename($filename);

            if (is_file($path)) {
                return \Base::instance()
                    ->get('BASE')
                    . "/avatar/{$size}-"
                    . (int) $this->id
                    . '.png';
            }
        }

        return \Helper\View::instance()
            ->gravatar(
                (string) $this->get('email'),
                $size
            );
    }

    public function getAll(): array
    {
        return $this->find(
            "deleted_date IS NULL AND role != 'group'",
            [
                'order' => 'name ASC',
            ]
        );
    }

    public function getAllDeleted(): array
    {
        return $this->find(
            "deleted_date IS NOT NULL AND role != 'group'",
            [
                'order' => 'name ASC',
            ]
        );
    }

    public function getAllGroups(): array
    {
        return $this->find(
            "deleted_date IS NULL AND role = 'group'",
            [
                'order' => 'name ASC',
            ]
        );
    }

    public function getGroupUsers()
    {
        if ($this->role !== 'group') {
            return null;
        }

        if ($this->_groupUsers !== null) {
            return $this->_groupUsers;
        }

        if (!$this->id) {
            return $this->_groupUsers = [];
        }

        $group =
            new User\Group();

        $members =
            $group->find([
                'group_id = ?',
                (int) $this->id,
            ]);

        $userIds = [];

        foreach ($members as $member) {
            $id = filter_var(
                $member->user_id,
                FILTER_VALIDATE_INT,
                [
                    'options' => [
                        'min_range' => 1,
                    ],
                ]
            );

            if ($id !== false) {
                $userIds[$id] = $id;
            }
        }

        if ($userIds === []) {
            return $this->_groupUsers = [];
        }

        $placeholders =
            implode(
                ',',
                array_fill(
                    0,
                    count($userIds),
                    '?'
                )
            );

        return $this->_groupUsers =
            $this->find(
                [
                    "id IN ({$placeholders}) "
                    . 'AND deleted_date IS NULL',
                    ...array_values($userIds),
                ]
            );
    }

    public function getGroupUserIds()
    {
        if ($this->role !== 'group') {
            return null;
        }

        $users =
            $this->getGroupUsers();

        if (!is_array($users)) {
            return [];
        }

        $ids = [];

        foreach ($users as $user) {
            if ($user->id) {
                $ids[] =
                    (int) $user->id;
            }
        }

        return array_values(
            array_unique($ids)
        );
    }

    public function getSharedGroupUserIds(): array
    {
        if (!$this->id) {
            return [];
        }

        $groupModel =
            new User\Group();

        $groups =
            $groupModel->find([
                'user_id = ?',
                (int) $this->id,
            ]);

        $groupIds = [];

        foreach ($groups as $group) {
            $id =
                (int) $group['group_id'];

            if ($id > 0) {
                $groupIds[$id] = $id;
            }
        }

        $ids = [
            (int) $this->id =>
                (int) $this->id,
        ];

        foreach ($groupIds as $groupId) {
            $ids[$groupId] =
                $groupId;
        }

        if ($groupIds === []) {
            return array_values($ids);
        }

        $placeholders =
            implode(
                ',',
                array_fill(
                    0,
                    count($groupIds),
                    '?'
                )
            );

        $members =
            $groupModel->find(
                [
                    "group_id IN ({$placeholders})",
                    ...array_values($groupIds),
                ]
            );

        foreach ($members as $member) {
            $userId =
                (int) $member->user_id;

            if ($userId > 0) {
                $ids[$userId] =
                    $userId;
            }
        }

        return array_values($ids);
    }

    public function options(): array
    {
        if (
            !is_string($this->options)
            || $this->options === ''
        ) {
            return [];
        }

        try {
            $options =
                json_decode(
                    $this->options,
                    true,
                    64,
                    JSON_THROW_ON_ERROR
                );

            return is_array($options)
                ? $options
                : [];
        } catch (\JsonException) {
            return [];
        }
    }

    public function option(
        string $key,
        $value = null
    ) {
        $key = trim($key);

        if (
            $key === ''
            || strlen($key) > 128
        ) {
            throw new \InvalidArgumentException(
                'Invalid option key.'
            );
        }

        $options =
            $this->options();

        if ($value === null) {
            return $options[$key]
                ?? null;
        }

        $options[$key] = $value;

        $this->options =
            json_encode(
                $options,
                JSON_THROW_ON_ERROR
            );

        return $this;
    }

    public function sendDueAlert(
        string $date = ''
    ): bool {
        if (!$this->id) {
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

        if (
            preg_match(
                '/\A\d{4}-\d{2}-\d{2}\z/D',
                $date
            ) !== 1
        ) {
            return false;
        }

        $ownerIds = [
            (int) $this->id,
        ];

        $groups =
            new User\Group();

        foreach (
            $groups->find([
                'user_id = ?',
                (int) $this->id,
            ]) as $row
        ) {
            $id =
                (int) $row->group_id;

            if ($id > 0) {
                $ownerIds[] = $id;
            }
        }

        $ownerIds =
            array_values(
                array_unique(
                    array_filter(
                        $ownerIds
                    )
                )
            );

        if ($ownerIds === []) {
            return false;
        }

        /*
         * IDs originate from integer-normalized database fields.
         */
        $ownerString =
            implode(
                ',',
                $ownerIds
            );

        $issue =
            new Issue();

        $due =
            $issue->find(
                [
                    "due_date = ? "
                    . "AND owner_id IN ({$ownerString}) "
                    . 'AND closed_date IS NULL '
                    . 'AND deleted_date IS NULL',
                    $date,
                ],
                [
                    'order' =>
                        'priority DESC',
                ]
            );

        $overdue =
            $issue->find(
                [
                    "due_date < ? "
                    . "AND owner_id IN ({$ownerString}) "
                    . 'AND closed_date IS NULL '
                    . 'AND deleted_date IS NULL',
                    $date,
                ],
                [
                    'order' =>
                        'priority DESC',
                ]
            );

        if (!$due && !$overdue) {
            return false;
        }

        $notification =
            new \Helper\Notification();

        return $notification
            ->user_due_issues(
                $this,
                $due,
                $overdue
            );
    }

    public function stats(
        int $time = 0
    ): array {
        $offset =
            \Helper\View::instance()
                ->timeoffset();

        if ($time === 0) {
            $time = strtotime(
                '-2 weeks',
                time() + $offset
            );
        }

        $result = [];

        $dateExpression = [
            'DATE(DATE_ADD(',
            ', INTERVAL :offset SECOND))',
        ];

        if (
            \Base::instance()
                ->get('db.engine')
            === 'sqlite'
        ) {
            $dateExpression = [
                'DATE(',
                ", :offset || ' seconds')",
            ];
        }

        $params = [
            ':user' =>
                (int) $this->id,

            ':offset' =>
                $offset,

            ':date' =>
                date(
                    'Y-m-d H:i:s',
                    $time
                ),
        ];

        $result['spent'] =
            $this->db->exec(
                "SELECT {$dateExpression[0]}u.created_date{$dateExpression[1]} AS `date`,
                        SUM(f.new_value - f.old_value) AS `val`
                 FROM issue_update u
                 JOIN issue_update_field f
                   ON u.id = f.issue_update_id
                  AND f.field = 'hours_spent'
                 WHERE u.user_id = :user
                   AND u.created_date > :date
                 GROUP BY `date`",
                $params
            );

        $result['closed'] =
            $this->db->exec(
                "SELECT {$dateExpression[0]}i.closed_date{$dateExpression[1]} AS `date`,
                        COUNT(*) AS `val`
                 FROM issue i
                 WHERE i.owner_id = :user
                   AND i.closed_date > :date
                 GROUP BY `date`",
                $params
            );

        $result['created'] =
            $this->db->exec(
                "SELECT {$dateExpression[0]}i.created_date{$dateExpression[1]} AS `date`,
                        COUNT(*) AS `val`
                 FROM issue i
                 WHERE i.author_id = :user
                   AND i.created_date > :date
                 GROUP BY `date`",
                $params
            );

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

        $return = [
            'labels' => [],
            'spent' => [],
            'closed' => [],
            'created' => [],
        ];

        foreach (
            $result['spent']
            as $row
        ) {
            $return['spent'][$row['date']] =
                (float) $row['val'];
        }

        foreach (
            $result['closed']
            as $row
        ) {
            $return['closed'][$row['date']] =
                (int) $row['val'];
        }

        foreach (
            $result['created']
            as $row
        ) {
            $return['created'][$row['date']] =
                (int) $row['val'];
        }

        foreach ($dates as $date) {
            $return['labels'][$date] =
                date(
                    'D j',
                    strtotime(
                        (string) $date
                    )
                );

            $return['spent'][$date] ??= 0;
            $return['closed'][$date] ??= 0;
            $return['created'][$date] ??= 0;
        }

        foreach (
            $return as &$values
        ) {
            ksort($values);
        }

        unset($values);

        return $return;
    }

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
            && $userId <= 0
        ) {
            throw new \InvalidArgumentException(
                'Invalid destination user.'
            );
        }

        $issueModel =
            new Issue();

        $issues =
            $issueModel->find([
                'owner_id = ? '
                . 'AND deleted_date IS NULL '
                . 'AND closed_date IS NULL',
                (int) $this->id,
            ]);

        foreach ($issues as $issue) {
            $issue->owner_id =
                $userId;

            $issue->save();
        }

        return count($issues);
    }

    public function date_picker()
    {
        $language =
            $this->language
            ?: \Base::instance()
                ->get('LANGUAGE');

        $language =
            explode(
                ',',
                (string) $language,
                2
            )[0];

        $language =
            preg_replace(
                '/[^a-zA-Z0-9_-]/',
                '',
                $language
            );

        if (!$language) {
            $language = 'en';
        }

        return (object) [
            'language' =>
                $language,

            'js' =>
                $language !== 'en',
        ];
    }
}
