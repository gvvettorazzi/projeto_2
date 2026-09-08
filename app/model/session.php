<?php

declare(strict_types=1);

namespace Model;

/**
 * Class Session
 *
 * @property int $id
 * @property string $token
 * @property string $ip
 * @property int $user_id
 * @property string $created
 */
class Session extends \Model
{
    protected $_table_name = 'session';

    public const COOKIE_NAME = 'phproj_token';

    /**
     * 256 bits of entropy.
     *
     * The browser receives the raw token.
     * The database stores only its SHA-256 digest.
     */
    private const TOKEN_BYTES = 32;

    /**
     * Maximum accepted cookie token size.
     */
    private const MAX_TOKEN_LENGTH = 128;

    /**
     * Minimum allowed session lifetime.
     */
    private const MIN_SESSION_LIFETIME = 300;

    /**
     * Maximum session lifetime: 30 days.
     */
    private const MAX_SESSION_LIFETIME = 2592000;

    /**
     * Raw token exists only in memory long enough
     * to be sent to the browser.
     *
     * It is never persisted in the database.
     */
    private ?string $rawToken = null;

    /**
     * Create a new authenticated session.
     */
    public function __construct(
        ?int $user_id = null,
        bool $auto_save = true
    ) {
        parent::__construct();

        if ($user_id === null) {
            return;
        }

        if ($user_id <= 0) {
            throw new \InvalidArgumentException(
                'Invalid user identifier.'
            );
        }

        /*
         * Ensure an authentication session cannot be created for
         * a deleted or nonexistent account.
         */
        $user = new User();

        $user->load([
            'id = ? AND deleted_date IS NULL',
            $user_id,
        ]);

        if (!$user->id) {
            throw new \RuntimeException(
                'Unable to create session.'
            );
        }

        $this->user_id = $user_id;

        /*
         * Generate a new cryptographically secure random token.
         */
        $this->rawToken = self::generateToken();

        /*
         * Only the digest is persisted.
         *
         * A database leak therefore does not directly provide
         * usable browser session tokens.
         */
        $this->token = self::tokenDigest(
            $this->rawToken
        );

        $this->ip = self::currentIp();

        $this->created = date(
            'Y-m-d H:i:s'
        );

        if ($auto_save) {
            $this->save();
        }
    }

    /**
     * Load and validate the current browser session.
     */
    public function loadCurrent(): Session
    {
        $f3 = \Base::instance();

        $rawToken = $f3->get(
            'COOKIE.' . self::COOKIE_NAME
        );

        if (
            !is_string($rawToken)
            || !self::validTokenFormat($rawToken)
        ) {
            return $this;
        }

        /*
         * The DB contains only the digest.
         */
        $digest = self::tokenDigest(
            $rawToken
        );

        $this->load([
            'token = ?',
            $digest,
        ]);

        if (!$this->id) {
            /*
             * Invalid cookie: remove it without revealing
             * whether a corresponding session ever existed.
             */
            self::expireCookie();

            return $this;
        }

        /*
         * Verify the stored digest using a timing-resistant
         * comparison as defense in depth.
         */
        if (
            !is_string($this->token)
            || !hash_equals(
                $this->token,
                $digest
            )
        ) {
            $this->invalidate();

            return $this;
        }

        /*
         * Ensure the referenced user is still active.
         */
        if (!$this->hasValidUser()) {
            $this->invalidate();

            return $this;
        }

        $createdTimestamp = strtotime(
            (string) $this->created
        );

        if ($createdTimestamp === false) {
            $this->invalidate();

            return $this;
        }

        $lifetime =
            self::sessionLifetime();

        $duration =
            time() - $createdTimestamp;

        /*
         * Reject clock-corrupted/future session records.
         */
        if ($duration < -60) {
            $this->invalidate();

            return $this;
        }

        /*
         * Expired session.
         */
        if ($duration >= $lifetime) {
            $this->invalidate();

            return $this;
        }

        /*
         * Rotate the token once half of the lifetime has elapsed.
         *
         * Token rotation limits the useful lifetime of a stolen token.
         */
        if ($duration >= ($lifetime / 2)) {
            $this->rotateToken();
        }

        return $this;
    }

    /**
     * Send the current session token to the browser.
     */
    public function setCurrent(): Session
    {
        /*
         * Never place the database digest in the browser.
         *
         * setCurrent() must only operate when a fresh plaintext
         * token exists in memory.
         */
        if (
            $this->rawToken === null
            || !self::validTokenFormat(
                $this->rawToken
            )
        ) {
            return $this;
        }

        self::writeCookie(
            $this->rawToken
        );

        $this->logSecurityEvent(
            'Session cookie set'
        );

        return $this;
    }

    /**
     * Rotate the session token.
     *
     * The previous token becomes invalid immediately.
     */
    public function rotateToken(): Session
    {
        if (!$this->id) {
            return $this;
        }

        $this->rawToken =
            self::generateToken();

        $this->token =
            self::tokenDigest(
                $this->rawToken
            );

        $this->created =
            date('Y-m-d H:i:s');

        $this->ip =
            self::currentIp();

        $this->save();

        $this->setCurrent();

        $this->logSecurityEvent(
            'Session token rotated'
        );

        return $this;
    }

    /**
     * Delete/invalidate session.
     */
    public function delete(): Session
    {
        if (!$this->id) {
            self::expireCookie();

            return $this;
        }

        $f3 = \Base::instance();

        $cookieToken = $f3->get(
            'COOKIE.' . self::COOKIE_NAME
        );

        /*
         * Only remove the browser cookie when it corresponds
         * to this session.
         */
        if (
            is_string($cookieToken)
            && self::validTokenFormat(
                $cookieToken
            )
            && is_string($this->token)
        ) {
            $cookieDigest =
                self::tokenDigest(
                    $cookieToken
                );

            if (
                hash_equals(
                    $this->token,
                    $cookieDigest
                )
            ) {
                self::expireCookie();
            }
        }

        $sessionId =
            (int) $this->id;

        parent::delete();

        /*
         * Never log tokens or the complete model.
         */
        $this->logSecurityEvent(
            'Session deleted',
            $sessionId
        );

        $this->rawToken = null;

        return $this;
    }

    /**
     * Explicitly invalidate a compromised or unusable session.
     */
    private function invalidate(): void
    {
        $sessionId =
            (int) ($this->id ?? 0);

        if ($this->id) {
            parent::delete();
        }

        self::expireCookie();

        $this->rawToken = null;

        $this->logSecurityEvent(
            'Session invalidated',
            $sessionId
        );
    }

    /**
     * Verify that the session still belongs to an active user.
     */
    private function hasValidUser(): bool
    {
        $userId = filter_var(
            $this->user_id,
            FILTER_VALIDATE_INT,
            [
                'options' => [
                    'min_range' => 1,
                ],
            ]
        );

        if ($userId === false) {
            return false;
        }

        $user = new User();

        $user->load([
            'id = ? AND deleted_date IS NULL',
            $userId,
        ]);

        return (bool) $user->id;
    }

    /**
     * Generate a cryptographically secure session token.
     */
    private static function generateToken(): string
    {
        return bin2hex(
            random_bytes(
                self::TOKEN_BYTES
            )
        );
    }

    /**
     * Generate the digest persisted in the database.
     *
     * SHA-256 is appropriate here because the input is already a
     * cryptographically random 256-bit token and is not a password.
     */
    private static function tokenDigest(
        string $token
    ): string {
        return hash(
            'sha256',
            $token
        );
    }

    /**
     * Validate the externally supplied session token.
     *
     * raw token = 32 bytes represented as 64 hexadecimal characters.
     */
    private static function validTokenFormat(
        string $token
    ): bool {
        if (
            $token === ''
            || strlen($token) >
                self::MAX_TOKEN_LENGTH
        ) {
            return false;
        }

        return preg_match(
            '/^[a-f0-9]{64}$/D',
            $token
        ) === 1;
    }

    /**
     * Safely obtain configured session lifetime.
     */
    private static function sessionLifetime(): int
    {
        $configured = filter_var(
            \Base::instance()->get(
                'session_lifetime'
            ),
            FILTER_VALIDATE_INT
        );

        if ($configured === false) {
            /*
             * Secure default: two hours.
             */
            return 7200;
        }

        return max(
            self::MIN_SESSION_LIFETIME,
            min(
                (int) $configured,
                self::MAX_SESSION_LIFETIME
            )
        );
    }

    /**
     * Write an authentication cookie with secure attributes.
     */
    private static function writeCookie(
        string $token
    ): void {
        if (headers_sent()) {
            throw new \RuntimeException(
                'Unable to establish secure session.'
            );
        }

        $lifetime =
            self::sessionLifetime();

        setcookie(
            self::COOKIE_NAME,
            $token,
            [
                'expires' =>
                    time() + $lifetime,

                'path' =>
                    '/',

                'secure' =>
                    self::isHttps(),

                'httponly' =>
                    true,

                /*
                 * Lax normally provides a good balance for standard
                 * web applications while reducing CSRF exposure.
                 */
                'samesite' =>
                    'Lax',
            ]
        );

        /*
         * Keep F3's current request state synchronized.
         */
        \Base::instance()->set(
            'COOKIE.' . self::COOKIE_NAME,
            $token
        );
    }

    /**
     * Delete the authentication cookie securely.
     */
    private static function expireCookie(): void
    {
        if (!headers_sent()) {
            setcookie(
                self::COOKIE_NAME,
                '',
                [
                    'expires' =>
                        time() - 3600,

                    'path' =>
                        '/',

                    'secure' =>
                        self::isHttps(),

                    'httponly' =>
                        true,

                    'samesite' =>
                        'Lax',
                ]
            );
        }

        \Base::instance()->set(
            'COOKIE.' . self::COOKIE_NAME,
            ''
        );
    }

    /**
     * Determine whether the current request is HTTPS.
     */
    private static function isHttps(): bool
    {
        $f3 = \Base::instance();

        $scheme = strtolower(
            (string) $f3->get('SCHEME')
        );

        if ($scheme === 'https') {
            return true;
        }

        $https = strtolower(
            (string) $f3->get(
                'SERVER.HTTPS'
            )
        );

        return $https !== ''
            && $https !== 'off'
            && $https !== '0';
    }

    /**
     * Obtain the current client IP for auditing.
     *
     * The IP is not used as the sole session authentication factor,
     * since legitimate addresses may change during a session.
     */
    private static function currentIp(): string
    {
        $ip = \Base::instance()->get(
            'IP'
        );

        if (!is_string($ip)) {
            return '';
        }

        $ip = trim($ip);

        if (
            filter_var(
                $ip,
                FILTER_VALIDATE_IP
            ) === false
        ) {
            return '';
        }

        /*
         * Maximum textual IPv6 length is 45 characters.
         */
        return substr(
            $ip,
            0,
            45
        );
    }

    /**
     * Security logging without exposing secrets.
     */
    private function logSecurityEvent(
        string $message,
        ?int $sessionId = null
    ): void {
        $f3 = \Base::instance();

        if (!$f3->get('DEBUG')) {
            return;
        }

        $sessionId ??=
            (int) ($this->id ?? 0);

        $userId =
            (int) ($this->user_id ?? 0);

        $log = new \Log(
            'session.log'
        );

        /*
         * Never log:
         * - session token
         * - cookie contents
         * - complete model cast
         * - authentication secrets
         */
        $log->write(
            sprintf(
                '%s; session_id=%d; user_id=%d',
                $message,
                $sessionId,
                $userId
            )
        );
    }
}
