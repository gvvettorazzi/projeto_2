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

    private const RESET_TOKEN_HASH_LENGTH = 96;

    protected $_table_name = 'user';

    protected $_groupUsers = null;

    /**
     * Load currently logged-in user, if any.
     */
    public function loadCurrent(): static
    {
        $f3 = \Base::instance();

        $session = new Session();
        $session->loadCurrent();

        $userId = (int) ($session->user_id ?? 0);

        if ($userId <= 0) {
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

        if ($this->exists('language') && !empty($this->language)) {
            $f3->set('LANGUAGE', $this->language);
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

        $size = max(1, $size);

        $avatarFilename = (string) $this->get('avatar_filename');

        if ($avatarFilename !== '') {
            $avatarPath = 'uploads/avatars/' . basename($avatarFilename);

            if (is_file($avatarPath)) {
                return sprintf(
                    '%s/avatar/%d-%d.png',
                    \Base::instance()->get('BASE'),
                    $size,
                    $this->id
                );
            }
        }

        return \Helper\View::instance()->gravatar(
            (string) $this->get('email'),
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
            ['order' => 'name ASC']
        );
    }

    /**
     * Load all deleted users.
     */
    public function getAllDeleted(): array
    {
        return $this->find(
            "deleted_date IS NOT NULL AND role != 'group'",
            ['order' => 'name ASC']
        );
    }

    /**
     * Load all active groups.
     */
    public function getAllGroups(): array
    {
        return $this->find(
            "deleted_date IS NULL AND role = 'group'",
            ['order' => 'name ASC']
        );
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

        $groupUserModel = new User\Group();

        /** @var User\Group[] $users */
        $users = $groupUserModel->find([
            'group_id = ?',
            $this->id,
        ]);

        if (!$users) {
            return $this->_groupUsers = [];
        }

        $userIds = [];

        foreach ($users as $user) {
            $userId = (int) $user->user_id;

            if ($userId > 0) {
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

        return $this->_groupUsers = $this->find([
            "id IN ({$placeholders}) AND deleted_date IS NULL",
            ...$userIds,
        ]);
    }

    /**
     * Get array of IDs of users within a group.
     *
     * @return array|null
     */
    public function getGroupUserIds(): ?array
    {
        $groupUsers = $this->getGroupUsers();

        if ($groupUsers === null) {
            return null;
        }

        $ids = [];

        foreach ($groupUsers as $user) {
            $userId = (int) $user->id;

            if ($userId > 0) {
                $ids[] = $userId;
            }
        }

        return array_values(array_unique($ids));
    }

    /**
     * Get all user IDs in groups shared with this user,
     * together with all group IDs the user belongs to.
     */
    public function getSharedGroupUserIds(): array
    {
        if (!$this->id) {
            return [];
        }

        $groupModel = new User\Group();

        $groups = $groupModel->find([
            'user_id = ?',
            $this->id,
        ]);

        $groupIds = [];

        foreach ($groups as $group) {
            $groupId = (int) $group->group_id;

            if ($groupId > 0) {
                $groupIds[] = $groupId;
            }
        }

        $groupIds = array_values(array_unique($groupIds));

        if ($groupIds === []) {
            return [$this->id];
        }

        $ids = $groupIds;

        $placeholders = implode(
            ',',
            array_fill(0, count($groupIds), '?')
        );

        $users = $groupModel->find([
            "group_id IN ({$placeholders})",
            ...$groupIds,
        ]);

        foreach ($users as $user) {
            $userId = (int) $user->user_id;

            if ($userId > 0) {
                $ids[] = $userId;
            }
        }

        $ids[] = (int) $this->id;

        return array_values(array_unique($ids));
    }

    /**
     * Get all user options.
     */
    public function options(): array
    {
        if (!$this->options) {
            return [];
        }

        try {
            $options = json_decode(
                $this->options,
                true,
                512,
                JSON_THROW_ON_ERROR
            );

            return is_array($options) ? $options : [];
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
        $key = trim($key);

        if ($key === '') {
            return $value === null ? null : $this;
        }

        $options = $this->options();

        if ($value === null) {
            return $options[$key] ?? null;
        }

        $options[$key] = $value;

        $this->options = json_encode(
            $options,
            JSON_THROW_ON_ERROR
        );

        return $this;
    }

    /**
     * Send an email alert with issues due on the given date.
     */
    public function sendDueAlert(string $date = ''): bool
    {
        if (!$this->id) {
            return false;
        }

        if ($date === '' || $date === '0') {
            $date = date(
                'Y-m-d',
                \Helper\View::instance()->utc2local()
            );
        }

        $ownerIds = [(int) $this->id];

        $groups = new User\Group();

        foreach ($groups->find(['user_id = ?', $this->id]) as $group) {
            $groupId = (int) $group->group_id;

            if ($groupId > 0) {
                $ownerIds[] = $groupId;
            }
        }

        $ownerIds = array_values(array_unique($ownerIds));

        $placeholders = implode(
            ',',
            array_fill(0, count($ownerIds), '?')
        );

        $parameters = array_merge([$date], $ownerIds);

        $issue = new Issue();

        $due = $issue->find(
            [
                "due_date = ? AND owner_id IN ({$placeholders})
                AND closed_date IS NULL
                AND deleted_date IS NULL",
                ...$parameters,
            ],
            ['order' => 'priority DESC']
        );

        $overdue = $issue->find(
            [
                "due_date < ? AND owner_id IN ({$placeholders})
                AND closed_date IS NULL
                AND deleted_date IS NULL",
                ...$parameters,
            ],
            ['order' => 'priority DESC']
        );

        if (!$due && !$overdue) {
            return false;
        }

        $notification = new \Helper\Notification();

        return $notification->user_due_issues(
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
        $offset = \Helper\View::instance()->timeoffset();

        if ($time <= 0) {
            $time = strtotime(
                '-2 weeks',
                time() + $offset
            );
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

        $dateStart = date('Y-m-d H:i:s', $time);

        $result = [];

        $result['spent'] = $this->db->exec(
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
            [
                ':user' => $this->id,
                ':offset' => $offset,
                ':date' => $dateStart,
            ]
        );

        $result['closed'] = $this->db->exec(
            "SELECT
                {$dateExpression[0]}i.closed_date{$dateExpression[1]} AS `date`,
                COUNT(*) AS `val`
            FROM issue i
            WHERE
                i.owner_id = :user
                AND i.closed_date > :date
            GROUP BY `date`",
            [
                ':user' => $this->id,
                ':offset' => $offset,
                ':date' => $dateStart,
            ]
        );

        $result['created'] = $this->db->exec(
            "SELECT
                {$dateExpression[0]}i.created_date{$dateExpression[1]} AS `date`,
                COUNT(*) AS `val`
            FROM issue i
            WHERE
                i.author_id = :user
                AND i.created_date > :date
            GROUP BY `date`",
            [
                ':user' => $this->id,
                ':offset' => $offset,
                ':date' => $dateStart,
            ]
        );

        $dates = $this->_createDateRangeArray(
            date('Y-m-d', $time),
            date('Y-m-d', time() + $offset)
        );

        $return = [
            'labels' => [],
            'spent' => [],
            'closed' => [],
            'created' => [],
        ];

        foreach ($result['spent'] as $row) {
            $return['spent'][$row['date']] = (float) $row['val'];
        }

        foreach ($result['closed'] as $row) {
            $return['closed'][$row['date']] = (int) $row['val'];
        }

        foreach ($result['created'] as $row) {
            $return['created'][$row['date']] = (int) $row['val'];
        }

        foreach ($dates as $date) {
            $date = (string) $date;

            $return['labels'][$date] = date(
                'D j',
                strtotime($date)
            );

            $return['spent'][$date] ??= 0;
            $return['closed'][$date] ??= 0;
            $return['created'][$date] ??= 0;
        }

        foreach ($return as &$values) {
            ksort($values);
        }

        unset($values);

        return $return;
    }

    /**
     * Reassign open assigned issues.
     *
     * @return int Number of issues affected.
     *
     * @throws \RuntimeException
     */
    public function reassignIssues(?int $userId): int
    {
        if (!$this->id) {
            throw new \RuntimeException(
                'User is not initialized.'
            );
        }

        if ($userId !== null && $userId <= 0) {
            throw new \InvalidArgumentException(
                'Invalid target user identifier.'
            );
        }

        $issueModel = new Issue();

        $issues = $issueModel->find([
            'owner_id = ? AND deleted_date IS NULL AND closed_date IS NULL',
            $this->id,
        ]);

        foreach ($issues as $issue) {
            $issue->owner_id = $userId;
            $issue->save();
        }

        return count($issues);
    }

    /**
     * Get date-picker language configuration.
     */
    public function date_picker(): object
    {
        $language = $this->language
            ?: \Base::instance()->get('LANGUAGE');

        $language = explode(
            ',',
            (string) $language,
            2
        )[0];

        $language = trim($language);

        if ($language === '') {
            $language = 'en';
        }

        return (object) [
            'language' => $language,
            'js' => $language !== 'en',
        ];
    }

    /**
     * Generate a password reset token and store its hashed value.
     */
    public function generateResetToken(): string
    {
        $random = random_bytes(64);

        $token = hash('sha384', $random)
            . (string) time();

        $this->reset_token = hash(
            'sha384',
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

        $ttl = (int) \Base::instance()->get(
            'security.reset_ttl'
        );

        if ($ttl <= 0) {
            return false;
        }

        $timestamp = substr(
            $token,
            self::RESET_TOKEN_HASH_LENGTH
        );

        if (
            $timestamp === ''
            || !ctype_digit($timestamp)
        ) {
            return false;
        }

        $timestamp = (int) $timestamp;
        $currentTime = time();

        $timestampValid =
            $timestamp <= $currentTime
            && $timestamp >= ($currentTime - $ttl);

        if (!$timestampValid) {
            return false;
        }

        $providedHash = hash(
            'sha384',
            $token
        );

        return hash_equals(
            (string) $this->reset_token,
            $providedHash
        );
    }
}
