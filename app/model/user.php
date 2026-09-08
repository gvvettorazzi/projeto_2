<?php

declare(strict_types=1);

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

    /**
     * Argon2id parameters based on OWASP recommendations.
     *
     * 19 MiB memory
     * 2 iterations
     * 1 thread
     */
    private const ARGON_MEMORY_COST = 19456;
    private const ARGON_TIME_COST = 2;
    private const ARGON_THREADS = 1;

    /**
     * Bcrypt fallback cost.
     */
    private const BCRYPT_COST = 12;

    /**
     * Maximum size accepted for a plaintext password.
     *
     * This prevents excessive resource consumption during hashing.
     */
    private const MAX_PASSWORD_LENGTH = 1024;

    /**
     * Password-reset token uses 256 bits of entropy.
     */
    private const RESET_TOKEN_BYTES = 32;

    /**
     * Authentication throttling.
     */
    private const MAX_AUTH_ATTEMPTS = 5;

    private const AUTH_WINDOW_SECONDS = 900;

    private const AUTH_BLOCK_SECONDS = 900;

    /**
     * Maximum allowed option key length.
     */
    private const MAX_OPTION_KEY_LENGTH = 128;

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

        $userId = self::positiveInt(
            $session->user_id ?? null
        );

        if ($userId === null) {
            $this->clearCurrentUserContext($f3);

            return $this;
        }

        $this->load([
            'id = ? AND deleted_date IS NULL',
            $userId,
        ]);

        if (!$this->id) {
            /*
             * Fail closed if the session references a user that no
             * longer exists or was deleted.
             */
            $this->clearCurrentUserContext($f3);

            return $this;
        }

        /*
         * Never copy secrets into the global F3 hive.
         */
        $f3->set(
            'user',
            $this->safeSessionData()
        );

        /*
         * Keep object compatibility with existing controllers.
         *
         * Code exposing this object to templates should still be avoided.
         */
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
     * Data safe to expose through the application session/hive.
     *
     * Sensitive authentication fields are explicitly removed.
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
     * Clear authentication context.
     */
    private function clearCurrentUserContext(
        \Base $f3
    ): void {
        $f3->clear('user');
        $f3->clear('user_obj');
    }

    /**
     * Hash and store a new password.
     *
     * Uses Argon2id when available and falls back to Bcrypt.
     */
    public function setPassword(
        string $plaintextPassword
    ): static {
        $plaintextPassword =
            self::validatePasswordInput(
                $plaintextPassword
            );

        $hash = self::hashPassword(
            $plaintextPassword
        );

        if ($hash === null) {
            throw new \RuntimeException(
                'Unable to securely hash password.'
            );
        }

        $this->password = $hash;

        /*
         * Modern password_hash() embeds its own salt.
         * Keeping the old salt field populated is unnecessary
         * and could cause legacy code to misuse it.
         */
        $this->salt = null;

        return $this;
    }

    /**
     * Verify a plaintext password.
     */
    public function verifyPassword(
        string $plaintextPassword
    ): bool {
        if (
            !$this->id
            || $this->deleted_date
            || !is_string($this->password)
            || $this->password === ''
        ) {
            /*
             * Execute a dummy password verification to make user state
             * differences less observable through timing.
             */
            self::dummyPasswordVerify(
                $plaintextPassword
            );

            return false;
        }

        if (!self::validPasswordLength($plaintextPassword)) {
            self::dummyPasswordVerify('');

            return false;
        }

        $valid = password_verify(
            $plaintextPassword,
            $this->password
        );

        if (!$valid) {
            return false;
        }

        /*
         * Automatically migrate weaker/older password_hash hashes
         * after a successful authentication.
         */
        if (
            self::passwordNeedsRehash(
                $this->password
            )
        ) {
            $this->setPassword(
                $plaintextPassword
            );

            $this->save();
        }

        return true;
    }

    /**
     * Hash a password securely.
     */
    private static function hashPassword(
        string $password
    ): ?string {
        try {
            if (
                defined('PASSWORD_ARGON2ID')
                && defined('PASSWORD_ARGON2_DEFAULT_MEMORY_COST')
            ) {
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
                 * Bcrypt processes at most 72 bytes.
                 */
                if (strlen($password) > 72) {
                    throw new \InvalidArgumentException(
                        'Password is too long for the configured hashing algorithm.'
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
        } catch (\Throwable) {
            return null;
        }

        return is_string($hash)
            ? $hash
            : null;
    }

    /**
     * Determine whether a stored password needs to be upgraded.
     */
    public static function passwordNeedsRehash(
        string $hash
    ): bool {
        if ($hash === '') {
            return true;
        }

        if (
            defined('PASSWORD_ARGON2ID')
            && defined('PASSWORD_ARGON2_DEFAULT_MEMORY_COST')
        ) {
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

    /**
     * Validate password input.
     */
    private static function validatePasswordInput(
        string $password
    ): string {
        if (!self::validPasswordLength($password)) {
            throw new \InvalidArgumentException(
                'Invalid password.'
            );
        }

        $configuredMinimum =
            filter_var(
                \Base::instance()->get(
                    'security.min_pass_len'
                ),
                FILTER_VALIDATE_INT
            );

        $minimum = $configuredMinimum === false
            ? 8
            : max(
                8,
                (int) $configuredMinimum
            );

        $length = function_exists('mb_strlen')
            ? mb_strlen(
                $password,
                'UTF-8'
            )
            : strlen($password);

        if ($length < $minimum) {
            throw new \InvalidArgumentException(
                'Password does not meet minimum length requirements.'
            );
        }

        /*
         * Do not trim passwords.
         * Leading/trailing spaces may intentionally form part
         * of the password.
         */
        return $password;
    }

    /**
     * Check safe password input bounds.
     */
    private static function validPasswordLength(
        string $password
    ): bool {
        return $password !== ''
            && strlen($password) <=
                self::MAX_PASSWORD_LENGTH;
    }

    /**
     * Dummy verification helps mitigate user enumeration through
     * observable password-processing timing differences.
     */
    public static function dummyPasswordVerify(
        string $password
    ): void {
        static $dummyHash = null;

        if ($dummyHash === null) {
            $dummyHash = password_hash(
                'phproject-dummy-authentication-value',
                PASSWORD_BCRYPT,
                [
                    'cost' => self::BCRYPT_COST,
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
     * Compare arbitrary secret values in constant time.
     */
    public static function secretsEqual(
        ?string $expected,
        ?string $provided
    ): bool {
        if (
            !is_string($expected)
            || !is_string($provided)
            || $expected === ''
            || $provided === ''
        ) {
            return false;
        }

        /*
         * Hash to fixed length first so length differences are not
         * directly observable by hash_equals().
         */
        return hash_equals(
            hash(
                'sha256',
                $expected
            ),
            hash(
                'sha256',
                $provided
            )
        );
    }

    /**
     * Verify an API key using timing-resistant comparison.
     *
     * This keeps compatibility with the existing plaintext api_key
     * column. A future database migration should store only a
     * one-way keyed digest instead.
     */
    public function verifyApiKey(
        string $providedKey
    ): bool {
        if (
            !$this->id
            || $this->deleted_date
            || !$this->api_visible
            || !is_string($this->api_key)
            || $this->api_key === ''
        ) {
            return false;
        }

        return self::secretsEqual(
            $this->api_key,
            $providedKey
        );
    }

    /**
     * Generate a cryptographically strong API key.
     */
    public function generateApiKey(): string
    {
        $key = bin2hex(
            random_bytes(32)
        );

        /*
         * Existing schema stores the API key as plaintext.
         *
         * Do not return this field through safeSessionData().
         */
        $this->api_key = $key;

        return $key;
    }

    /**
     * Generate a password-reset token.
     *
     * The plaintext token is returned only once.
     * Only its keyed digest is persisted.
     */
    public function generateResetToken(): string
    {
        $issuedAt = time();

        $random = bin2hex(
            random_bytes(
                self::RESET_TOKEN_BYTES
            )
        );

        $token =
            $random
            . '.'
            . $issuedAt;

        $this->reset_token =
            self::resetTokenDigest(
                $token
            );

        return $token;
    }

    /**
     * Validate password-reset token.
     */
    public function validateResetToken(
        string $token
    ): bool {
        $storedDigest =
            $this->reset_token;

        if (
            !is_string($storedDigest)
            || $storedDigest === ''
        ) {
            /*
             * Fixed amount of cryptographic processing before failing.
             */
            self::resetTokenDigest(
                $token
            );

            return false;
        }

        if (
            strlen($token) > 256
            || !preg_match(
                '/^[a-f0-9]{64}\.[0-9]{1,12}$/D',
                $token
            )
        ) {
            return false;
        }

        [$random, $timestamp] =
            explode(
                '.',
                $token,
                2
            );

        unset($random);

        $issuedAt = filter_var(
            $timestamp,
            FILTER_VALIDATE_INT
        );

        if ($issuedAt === false) {
            return false;
        }

        $ttl = self::resetTokenTtl();

        $now = time();

        /*
         * Reject tokens from the future and tokens outside TTL.
         */
        if (
            $issuedAt > ($now + 60)
            || $issuedAt < ($now - $ttl)
        ) {
            return false;
        }

        $expected =
            self::resetTokenDigest(
                $token
            );

        return hash_equals(
            $storedDigest,
            $expected
        );
    }

    /**
     * Invalidate a reset token immediately after use.
     */
    public function invalidateResetToken(): static
    {
        $this->reset_token = null;

        return $this;
    }

    /**
     * Generate keyed reset token digest.
     */
    private static function resetTokenDigest(
        string $token
    ): string {
        return hash_hmac(
            'sha256',
            $token,
            self::resetTokenSecret()
        );
    }

    /**
     * Reset-token secret must live outside the database.
     */
    private static function resetTokenSecret(): string
    {
        $f3 = \Base::instance();

        $secret = $f3->get(
            'security.reset_secret'
        );

        if (
            !is_string($secret)
            || strlen($secret) < 32
        ) {
            /*
             * Reuse the issue-integrity secret only as an explicit
             * backwards-compatible configuration fallback.
             *
             * A dedicated reset secret is preferable.
             */
            $secret = $f3->get(
                'security.issue_integrity_key'
            );
        }

        if (
            !is_string($secret)
            || strlen($secret) < 32
        ) {
            throw new \RuntimeException(
                'Password reset secret is not securely configured.'
            );
        }

        return $secret;
    }

    /**
     * Password-reset lifetime.
     */
    private static function resetTokenTtl(): int
    {
        $ttl = filter_var(
            \Base::instance()->get(
                'security.reset_ttl'
            ),
            FILTER_VALIDATE_INT
        );

        if (
            $ttl === false
            || $ttl < 60
            || $ttl > 86400
        ) {
            /*
             * Secure fallback: one hour.
             */
            return 3600;
        }

        return (int) $ttl;
    }

    /**
     * Check whether another authentication attempt is currently allowed.
     *
     * Call this BEFORE validating username/password.
     */
    public static function canAttemptAuthentication(
        string $identifier,
        ?string $clientAddress = null
    ): bool {
        $key =
            self::authenticationThrottleKey(
                $identifier,
                $clientAddress
            );

        $state =
            self::loadAuthenticationThrottleState(
                $key
            );

        if ($state === null) {
            return true;
        }

        $now = time();

        $blockedUntil =
            isset($state['blocked_until'])
                ? (int) $state['blocked_until']
                : 0;

        if ($blockedUntil > $now) {
            return false;
        }

        /*
         * Clear old attempt window.
         */
        $firstAttempt =
            isset($state['first_attempt'])
                ? (int) $state['first_attempt']
                : 0;

        if (
            $firstAttempt === 0
            || $firstAttempt <
                ($now - self::AUTH_WINDOW_SECONDS)
        ) {
            self::clearAuthenticationFailures(
                $identifier,
                $clientAddress
            );

            return true;
        }

        return true;
    }

    /**
     * Record failed authentication attempt.
     *
     * Call this after an invalid login.
     */
    public static function registerAuthenticationFailure(
        string $identifier,
        ?string $clientAddress = null
    ): void {
        $key =
            self::authenticationThrottleKey(
                $identifier,
                $clientAddress
            );

        $now = time();

        $state =
            self::loadAuthenticationThrottleState(
                $key
            ) ?? [
                'attempts' => 0,
                'first_attempt' => $now,
                'blocked_until' => 0,
            ];

        $firstAttempt =
            (int) (
                $state['first_attempt']
                    ?? $now
            );

        if (
            $firstAttempt <
            ($now - self::AUTH_WINDOW_SECONDS)
        ) {
            $state = [
                'attempts' => 0,
                'first_attempt' => $now,
                'blocked_until' => 0,
            ];
        }

        $state['attempts'] =
            (int) ($state['attempts'] ?? 0)
            + 1;

        if (
            $state['attempts'] >=
            self::MAX_AUTH_ATTEMPTS
        ) {
            $state['blocked_until'] =
                $now
                + self::AUTH_BLOCK_SECONDS;
        }

        \Cache::instance()->set(
            $key,
            $state,
            max(
                self::AUTH_WINDOW_SECONDS,
                self::AUTH_BLOCK_SECONDS
            )
        );
    }

    /**
     * Clear failed-login counter after successful authentication.
     */
    public static function clearAuthenticationFailures(
        string $identifier,
        ?string $clientAddress = null
    ): void {
        \Cache::instance()->clear(
            self::authenticationThrottleKey(
                $identifier,
                $clientAddress
            )
        );
    }

    /**
     * Load authentication throttle state.
     */
    private static function loadAuthenticationThrottleState(
        string $key
    ): ?array {
        $state =
            \Cache::instance()->get(
                $key
            );

        return is_array($state)
            ? $state
            : null;
    }

    /**
     * Build a non-reversible cache key for authentication throttling.
     *
     * Raw usernames, email addresses and IPs are not put into
     * cache keys or logs.
     */
    private static function authenticationThrottleKey(
        string $identifier,
        ?string $clientAddress
    ): string {
        $identifier =
            strtolower(
                trim($identifier)
            );

        $clientAddress =
            trim(
                (string) $clientAddress
            );

        /*
         * Per-account + per-source combination.
         *
         * Do not rely only on IP because distributed brute-force
         * attacks can rotate addresses.
         */
        $value =
            $identifier
            . '|'
            . $clientAddress;

        return 'auth.fail.'
            . hash_hmac(
                'sha256',
                $value,
                self::authenticationThrottleSecret()
            );
    }

    /**
     * Secret used to obscure authentication-throttle cache keys.
     */
    private static function authenticationThrottleSecret(): string
    {
        $f3 = \Base::instance();

        $secret = $f3->get(
            'security.auth_throttle_secret'
        );

        if (
            !is_string($secret)
            || strlen($secret) < 32
        ) {
            $secret = $f3->get(
                'security.reset_secret'
            );
        }

        if (
            !is_string($secret)
            || strlen($secret) < 32
        ) {
            throw new \RuntimeException(
                'Authentication throttle secret is not configured.'
            );
        }

        return $secret;
    }

    /**
     * Check authorization rank using least privilege.
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
            $requiredRank <
                self::RANK_GUEST
            || $requiredRank >
                self::RANK_SUPER
        ) {
            return false;
        }

        return (int) $this->rank
            >= $requiredRank;
    }

    /**
     * Require a minimum privilege level.
     */
    public function requireMinimumRank(
        int $requiredRank
    ): void {
        if (
            !$this->hasMinimumRank(
                $requiredRank
            )
        ) {
            throw new \RuntimeException(
                'Operation not permitted.'
            );
        }
    }

    /**
     * Get avatar path or Gravatar.
     *
     * @return string|bool
     */
    public function avatar(int $size = 80)
    {
        if (!$this->id) {
            return false;
        }

        /*
         * Restrict unreasonable image dimensions.
         */
        $size = max(
            16,
            min(
                $size,
                2048
            )
        );

        $avatar =
            $this->get(
                'avatar_filename'
            );

        if (
            is_string($avatar)
            && $avatar !== ''
        ) {
            /*
             * basename() prevents directory traversal if a corrupted
             * avatar_filename reaches the database.
             */
            $avatar = basename(
                $avatar
            );

            $path =
                'uploads/avatars/'
                . $avatar;

            if (is_file($path)) {
                return \Base::instance()
                    ->get('BASE')
                    . '/avatar/'
                    . $size
                    . '-'
                    . (int) $this->id
                    . '.png';
            }
        }

        return \Helper\View::instance()
            ->gravatar(
                $this->get('email'),
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
        );
    }

    /**
     * Load deleted users.
     *
     * Authorization should be enforced by the calling controller.
     */
    public function getAllDeleted(): array
    {
        return $this->find(
            "deleted_date IS NOT NULL AND role != 'group'",
            [
                'order' => 'name ASC',
            ]
        );
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
        );
    }

    /**
     * Get all users within a group.
     *
     * @return array|null
     */
    public function getGroupUsers()
    {
        if ($this->role !== 'group') {
            return null;
        }

        if (
            $this->_groupUsers !== null
        ) {
            return $this->_groupUsers;
        }

        $groupId =
            self::positiveInt($this->id);

        if ($groupId === null) {
            return [];
        }

        $membership =
            new User\Group();

        /** @var User\Group[] $memberships */
        $memberships =
            $membership->find([
                'group_id = ?',
                $groupId,
            ]);

        $userIds = [];

        foreach (
            $memberships as $membershipEntry
        ) {
            $userId =
                self::positiveInt(
                    $membershipEntry->user_id
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

        /*
         * Values are normalized integers before entering IN().
         */
        $idList =
            implode(
                ',',
                $userIds
            );

        return $this->_groupUsers =
            $this->find(
                "id IN ({$idList}) "
                . 'AND deleted_date IS NULL'
            );
    }

    /**
     * Get IDs of users within a group.
     *
     * @return array|null
     */
    public function getGroupUserIds()
    {
        if ($this->role !== 'group') {
            return null;
        }

        $users =
            $this->getGroupUsers();

        if (!is_iterable($users)) {
            return [];
        }

        $ids = [];

        foreach ($users as $user) {
            $userId =
                self::positiveInt(
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
     * Get users/groups sharing group membership.
     */
    public function getSharedGroupUserIds(): array
    {
        $currentUserId =
            self::positiveInt($this->id);

        if ($currentUserId === null) {
            return [];
        }

        $groupModel =
            new User\Group();

        $groups =
            $groupModel->find([
                'user_id = ?',
                $currentUserId,
            ]);

        $groupIds = [];

        foreach ($groups as $group) {
            $groupId =
                self::positiveInt(
                    $group->group_id
                    ?? $group['group_id']
                    ?? null
                );

            if ($groupId !== null) {
                $groupIds[] = $groupId;
            }
        }

        $groupIds = array_values(
            array_unique($groupIds)
        );

        $ids = [
            $currentUserId,
        ];

        if ($groupIds === []) {
            return $ids;
        }

        $groupIdString =
            implode(
                ',',
                $groupIds
            );

        $memberships =
            $groupModel->find(
                "group_id IN ({$groupIdString})"
            );

        foreach ($memberships as $membership) {
            $userId =
                self::positiveInt(
                    $membership->user_id
                    ?? null
                );

            if ($userId !== null) {
                $ids[] = $userId;
            }
        }

        return array_values(
            array_unique(
                array_merge(
                    $ids,
                    $groupIds
                )
            )
        );
    }

    /**
     * Decode stored user options safely.
     */
    public function options(): array
    {
        if (
            !is_string($this->options)
            || $this->options === ''
        ) {
            return [];
        }

        try {
            $decoded =
                json_decode(
                    $this->options,
                    true,
                    64,
                    JSON_THROW_ON_ERROR
                );
        } catch (\JsonException) {
            return [];
        }

        return is_array($decoded)
            ? $decoded
            : [];
    }

    /**
     * Get or set a user option.
     *
     * @param mixed $value
     * @return mixed
     */
    public function option(
        string $key,
        $value = null
    ) {
        $key = trim($key);

        if (
            $key === ''
            || strlen($key) >
                self::MAX_OPTION_KEY_LENGTH
            || preg_match(
                '/^[A-Za-z0-9_.-]+$/D',
                $key
            ) !== 1
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

        /*
         * Prevent objects/resources from being serialized into
         * security-sensitive user preferences.
         */
        if (
            is_resource($value)
            || is_object($value)
        ) {
            throw new \InvalidArgumentException(
                'Invalid option value.'
            );
        }

        $options[$key] =
            $value;

        $this->options =
            json_encode(
                $options,
                JSON_THROW_ON_ERROR
                | JSON_UNESCAPED_SLASHES
                | JSON_UNESCAPED_UNICODE
            );

        return $this;
    }

    /**
     * Send an email alert with issues due on the supplied date.
     */
    public function sendDueAlert(
        string $date = ''
    ): bool {
        $userId =
            self::positiveInt($this->id);

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
        } else {
            $date =
                self::normalizeDate($date);

            if ($date === null) {
                return false;
            }
        }

        $ownerIds = [
            $userId,
        ];

        $groups =
            new User\Group();

        foreach (
            $groups->find([
                'user_id = ?',
                $userId,
            ]) as $row
        ) {
            $groupId =
                self::positiveInt(
                    $row->group_id ?? null
                );

            if ($groupId !== null) {
                $ownerIds[] =
                    $groupId;
            }
        }

        $ownerIds = array_values(
            array_unique(
                $ownerIds
            )
        );

        $ownerStr =
            implode(
                ',',
                $ownerIds
            );

        $issue = new Issue();

        $due = $issue->find(
            [
                "due_date = ? "
                . "AND owner_id IN ({$ownerStr}) "
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
                    . "AND owner_id IN ({$ownerStr}) "
                    . 'AND closed_date IS NULL '
                    . 'AND deleted_date IS NULL',
                    $date,
                ],
                [
                    'order' =>
                        'priority DESC',
                ]
            );

        if (
            !$due
            && !$overdue
        ) {
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

    /**
     * Get user statistics.
     */
    public function stats(
        int $time = 0
    ): array {
        $userId =
            self::positiveInt($this->id);

        if ($userId === null) {
            return [
                'labels' => [],
                'spent' => [],
                'closed' => [],
                'created' => [],
            ];
        }

        $offset =
            \Helper\View::instance()
                ->timeoffset();

        if ($time <= 0) {
            $calculatedTime =
                strtotime(
                    '-2 weeks',
                    time() + $offset
                );

            $time =
                $calculatedTime === false
                    ? time() - 1209600
                    : $calculatedTime;
        }

        $dateExpr = [
            'DATE(DATE_ADD(',
            ', INTERVAL :offset SECOND))',
        ];

        if (
            \Base::instance()->get(
                'db.engine'
            ) === 'sqlite'
        ) {
            $dateExpr = [
                'DATE(',
                ", :offset || ' seconds')",
            ];
        }

        $params = [
            ':user' =>
                $userId,

            ':offset' =>
                $offset,

            ':date' =>
                date(
                    'Y-m-d H:i:s',
                    $time
                ),
        ];

        $result = [];

        $result['spent'] =
            $this->db->exec(
                "SELECT {$dateExpr[0]}"
                . "u.created_date{$dateExpr[1]} AS `date`, "
                . 'SUM(f.new_value - f.old_value) AS `val` '
                . 'FROM issue_update u '
                . 'JOIN issue_update_field f '
                . 'ON u.id = f.issue_update_id '
                . "AND f.field = 'hours_spent' "
                . 'WHERE u.user_id = :user '
                . 'AND u.created_date > :date '
                . 'GROUP BY `date`',
                $params
            );

        $result['closed'] =
            $this->db->exec(
                "SELECT {$dateExpr[0]}"
                . "i.closed_date{$dateExpr[1]} AS `date`, "
                . 'COUNT(*) AS `val` '
                . 'FROM issue i '
                . 'WHERE i.owner_id = :user '
                . 'AND i.closed_date > :date '
                . 'GROUP BY `date`',
                $params
            );

        $result['created'] =
            $this->db->exec(
                "SELECT {$dateExpr[0]}"
                . "i.created_date{$dateExpr[1]} AS `date`, "
                . 'COUNT(*) AS `val` '
                . 'FROM issue i '
                . 'WHERE i.author_id = :user '
                . 'AND i.created_date > :date '
                . 'GROUP BY `date`',
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
            $result['spent'] as $row
        ) {
            $return['spent'][$row['date']] =
                (float) $row['val'];
        }

        foreach (
            $result['closed'] as $row
        ) {
            $return['closed'][$row['date']] =
                (int) $row['val'];
        }

        foreach (
            $result['created'] as $row
        ) {
            $return['created'][$row['date']] =
                (int) $row['val'];
        }

        foreach ($dates as $date) {
            $timestamp =
                strtotime(
                    (string) $date
                );

            $return['labels'][$date] =
                $timestamp === false
                    ? (string) $date
                    : date(
                        'D j',
                        $timestamp
                    );

            $return['spent'][$date] =
                $return['spent'][$date]
                ?? 0;

            $return['closed'][$date] =
                $return['closed'][$date]
                ?? 0;

            $return['created'][$date] =
                $return['created'][$date]
                ?? 0;
        }

        foreach ($return as &$values) {
            ksort($values);
        }

        unset($values);

        return $return;
    }

    /**
     * Reassign open issues.
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
            && $userId <= 0
        ) {
            throw new \InvalidArgumentException(
                'Invalid destination user.'
            );
        }

        /*
         * Validate the destination account when provided.
         */
        if ($userId !== null) {
            $destination =
                new User();

            $destination->load([
                'id = ? AND deleted_date IS NULL',
                $userId,
            ]);

            if (
                !$destination->id
                || $destination->role === 'group'
            ) {
                throw new \InvalidArgumentException(
                    'Invalid destination user.'
                );
            }
        }

        $issueModel =
            new Issue();

        $issues =
            $issueModel->find([
                'owner_id = ? '
                . 'AND deleted_date IS NULL '
                . 'AND closed_date IS NULL',
                $this->id,
            ]);

        $count = 0;

        foreach ($issues as $issue) {
            if (
                !$issue instanceof Issue
            ) {
                continue;
            }

            $issue->owner_id =
                $userId;

            $issue->save();

            $count++;
        }

        return $count;
    }

    /**
     * Date picker configuration.
     */
    public function date_picker()
    {
        $lang =
            $this->language
            ?: \Base::instance()
                ->get('LANGUAGE');

        $lang =
            explode(
                ',',
                (string) $lang,
                2
            )[0];

        /*
         * Restrict locale component to a predictable format.
         */
        if (
            preg_match(
                '/^[A-Za-z]{2,3}(?:[-_][A-Za-z]{2})?$/D',
                $lang
            ) !== 1
        ) {
            $lang = 'en';
        }

        return (object) [
            'language' =>
                $lang,

            'js' =>
                $lang !== 'en',
        ];
    }

    /**
     * Validate a positive integer.
     */
    private static function positiveInt(
        mixed $value
    ): ?int {
        if (
            $value === null
            || $value === ''
        ) {
            return null;
        }

        $result =
            filter_var(
                $value,
                FILTER_VALIDATE_INT,
                [
                    'options' => [
                        'min_range' => 1,
                    ],
                ]
            );

        return $result === false
            ? null
            : (int) $result;
    }

    /**
     * Strictly normalize a calendar date.
     */
    private static function normalizeDate(
        string $date
    ): ?string {
        $date =
            trim($date);

        if (
            preg_match(
                '/^\d{4}-\d{2}-\d{2}$/D',
                $date
            ) !== 1
        ) {
            return null;
        }

        $parsed =
            \DateTimeImmutable::createFromFormat(
                '!Y-m-d',
                $date
            );

        $errors =
            \DateTimeImmutable::getLastErrors();

        if (
            !$parsed instanceof
                \DateTimeImmutable
        ) {
            return null;
        }

        if (
            $errors !== false
            && (
                $errors['warning_count'] > 0
                || $errors['error_count'] > 0
            )
        ) {
            return null;
        }

        return $parsed->format(
            'Y-m-d'
        ) === $date
            ? $date
            : null;
    }
}
