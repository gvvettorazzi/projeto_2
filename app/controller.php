<?php

declare(strict_types=1);

abstract class Controller
{
    /**
     * Require an authenticated user with at least the supplied rank.
     *
     * Redirects anonymous users to /login.
     * Returns the authenticated user ID when authorized.
     */
    protected function _requireLogin(
        int $rank = \Model\User::RANK_CLIENT
    ): int|bool {
        $f3 = \Base::instance();

        if (
            $rank < \Model\User::RANK_GUEST
            || $rank > \Model\User::RANK_SUPER
        ) {
            $f3->error(403);

            return false;
        }

        $user = $f3->get('user_obj');

        /*
         * Prefer the authenticated User model over values copied
         * into the global hive.
         */
        if ($user instanceof \Model\User) {
            $userId = filter_var(
                $user->id,
                FILTER_VALIDATE_INT,
                [
                    'options' => [
                        'min_range' => 1,
                    ],
                ]
            );

            if (
                $userId !== false
                && !$user->deleted_date
            ) {
                if (
                    $user->hasMinimumRank($rank)
                ) {
                    return (int) $userId;
                }

                $f3->error(403);

                return false;
            }
        }

        /*
         * Defensive cleanup.
         *
         * Avoid trusting stale hive values when the authenticated
         * User object is missing or invalid.
         */
        $f3->clear('user');
        $f3->clear('user_obj');

        if ($this->tryDemoLogin($rank)) {
            /*
             * Preserve original behavior: a demo auto-login creates
             * the session, but the current request does not continue
             * as though it had already passed the original auth check.
             */
            return false;
        }

        $this->redirectToLogin();

        return false;
    }

    /**
     * Attempt automatic login for the configured demo user.
     */
    private function tryDemoLogin(
        int $requiredRank
    ): bool {
        $f3 = \Base::instance();

        $demoValue = $f3->get(
            'site.demo'
        );

        $demoUserId = filter_var(
            $demoValue,
            FILTER_VALIDATE_INT,
            [
                'options' => [
                    'min_range' => 1,
                ],
            ]
        );

        if ($demoUserId === false) {
            return false;
        }

        $user = new \Model\User();

        $user->load([
            'id = ? AND deleted_date IS NULL',
            $demoUserId,
        ]);

        if (!$user->id) {
            /*
             * Avoid exposing implementation details to normal users.
             */
            if ($f3->get('DEBUG')) {
                $f3->set(
                    'error',
                    'Demo auto-login could not be completed.'
                );
            }

            return false;
        }

        /*
         * Demo mode must not bypass the privilege requirement of
         * the current route.
         */
        if (
            !$user->hasMinimumRank(
                $requiredRank
            )
        ) {
            $f3->error(403);

            return false;
        }

        try {
            $session = new \Model\Session(
                (int) $user->id
            );

            $session->setCurrent();
        } catch (\Throwable $exception) {
            /*
             * Never expose token/session exception details.
             */
            if ($f3->get('DEBUG')) {
                $log = new \Log(
                    'security.log'
                );

                $log->write(
                    sprintf(
                        'Demo session creation failed; user_id=%d; exception=%s',
                        (int) $user->id,
                        get_class($exception)
                    )
                );
            }

            return false;
        }

        /*
         * Never use $user->cast() here because it contains
         * authentication-related fields.
         */
        $f3->set(
            'user',
            $user->safeSessionData()
        );

        $f3->set(
            'user_obj',
            $user
        );

        if (
            $user->language
            && is_string($user->language)
        ) {
            $f3->set(
                'LANGUAGE',
                $user->language
            );
        }

        return true;
    }

    /**
     * Redirect an unauthenticated request to the login page.
     */
    private function redirectToLogin(): void
    {
        $f3 = \Base::instance();

        $path = (string) $f3->get(
            'PATH'
        );

        /*
         * Keep redirect destinations local to the application.
         */
        if (
            $path === ''
            || $path[0] !== '/'
            || str_starts_with($path, '//')
        ) {
            $path = '/';
        }

        $query = '';

        if ($_GET !== []) {
            /*
             * http_build_query handles URL encoding.
             *
             * Avoid concatenating unvalidated absolute URLs.
             */
            $query = '?' . http_build_query(
                $_GET,
                '',
                '&',
                PHP_QUERY_RFC3986
            );
        }

        $destination =
            $path . $query;

        $f3->reroute(
            '/login?to='
            . rawurlencode(
                $destination
            )
        );
    }

    /**
     * Require an administrator with at least the requested rank.
     */
    protected function _requireAdmin(
        int $rank = \Model\User::RANK_ADMIN
    ): int|bool {
        /*
         * An administrator requirement must never accept a rank
         * lower than RANK_ADMIN.
         */
        $rank = max(
            $rank,
            \Model\User::RANK_ADMIN
        );

        $id = $this->_requireLogin(
            $rank
        );

        if ($id === false) {
            return false;
        }

        $f3 = \Base::instance();

        $user = $f3->get(
            'user_obj'
        );

        if (
            !$user instanceof \Model\User
            || $user->deleted_date
        ) {
            $f3->error(403);

            return false;
        }

        /*
         * Preserve the application's existing administrator role
         * requirement while using strict comparisons.
         */
        if (
            $user->role !== 'admin'
            || !$user->hasMinimumRank($rank)
        ) {
            $f3->error(403);

            return false;
        }

        return (int) $id;
    }

    /**
     * Render a view.
     */
    protected function _render(
        string $file,
        string $mime = 'text/html',
        ?array $hive = null,
        int $ttl = 0
    ): void {
        /*
         * Prevent unexpected path manipulation at the controller
         * boundary.
         *
         * Views are expected to be application-relative paths.
         */
        if (!$this->isValidViewPath($file)) {
            throw new \InvalidArgumentException(
                'Invalid view.'
            );
        }

        if (
            $ttl < 0
            || $ttl > 86400
        ) {
            $ttl = 0;
        }

        echo \Helper\View::instance()->render(
            $file,
            $mime,
            $hive,
            $ttl
        );
    }

    /**
     * Validate a view path.
     */
    private function isValidViewPath(
        string $file
    ): bool {
        if (
            $file === ''
            || strlen($file) > 255
        ) {
            return false;
        }

        /*
         * Reject absolute paths, null bytes and directory traversal.
         */
        if (
            str_contains($file, "\0")
            || str_starts_with($file, '/')
            || str_contains($file, '..')
            || preg_match(
                '/^[A-Za-z]:[\\\\\/]/',
                $file
            ) === 1
        ) {
            return false;
        }

        return preg_match(
            '/^[A-Za-z0-9_.\/-]+$/D',
            $file
        ) === 1;
    }

    /**
     * Output a JSON response safely.
     *
     * @param mixed $object
     */
    protected function _printJson(
        $object
    ): void {
        if (!headers_sent()) {
            header(
                'Content-Type: application/json; charset=utf-8'
            );

            /*
             * Avoid MIME sniffing of JSON responses.
             */
            header(
                'X-Content-Type-Options: nosniff'
            );
        }

        try {
            echo json_encode(
                $object,
                JSON_THROW_ON_ERROR
                | JSON_UNESCAPED_SLASHES
                | JSON_UNESCAPED_UNICODE
                | JSON_HEX_TAG
                | JSON_HEX_AMP
                | JSON_HEX_APOS
                | JSON_HEX_QUOT
            );
        } catch (\JsonException) {
            if (!headers_sent()) {
                http_response_code(500);
            }

            /*
             * Do not expose serialization/internal exception data.
             */
            echo '{"error":"Unable to process response."}';
        }
    }

    /**
     * Get current server date/time.
     */
    public function now(
        bool $time = true
    ): string {
        return $time
            ? date('Y-m-d H:i:s')
            : date('Y-m-d');
    }

    /**
     * Validate the request CSRF token.
     */
    protected function validateCsrf(): void
    {
        /*
         * CSRF validation should only accept state-changing
         * requests from authenticated application flows.
         */
        $method = strtoupper(
            (string) \Base::instance()->get(
                'VERB'
            )
        );

        if (
            !in_array(
                $method,
                [
                    'POST',
                    'PUT',
                    'PATCH',
                    'DELETE',
                ],
                true
            )
        ) {
            /*
             * Preserve compatibility by simply returning for safe
             * request methods.
             */
            return;
        }

        \Helper\Security::instance()
            ->validateCsrfToken();
    }
}
