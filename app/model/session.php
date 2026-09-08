<?php

namespace Model;

class Session extends \Model
{
    public const COOKIE_NAME = 'phproj_token';

    private const TOKEN_BYTES = 32;

    /*
     * Limites defensivos para impedir configuração incorreta
     * de manter sessões indefinidamente.
     */
    private const DEFAULT_LIFETIME = 86400;      // 24 horas
    private const MAX_LIFETIME = 2592000;        // 30 dias
    private const ROTATION_DIVISOR = 2;

    protected $_table_name = 'session';

    /**
     * Token em texto puro existe apenas durante a requisição
     * que cria ou rotaciona a sessão.
     *
     * O banco recebe somente SHA-256(token).
     */
    private ?string $rawToken = null;

    /**
     * Cria uma nova sessão autenticada.
     */
    public function __construct(
        ?int $user_id = null,
        bool $auto_save = true
    ) {
        parent::__construct();

        if ($user_id === null) {
            return;
        }

        $userId = self::validateUserId($user_id);

        if ($userId === null) {
            throw new \InvalidArgumentException(
                'Invalid user.'
            );
        }

        /*
         * Nunca criar sessão para usuário inexistente
         * ou excluído.
         */
        $user = new User();

        $user->load([
            'id = ? AND deleted_date IS NULL',
            $userId,
        ]);

        if (!$user->id) {
            throw new \RuntimeException(
                'Unable to create session.'
            );
        }

        $this->user_id = $userId;

        $this->created = date(
            'Y-m-d H:i:s'
        );

        $this->ip = self::currentIp();

        $this->generateToken();

        if ($auto_save) {
            parent::save();
        }
    }

    /**
     * Carrega e valida a sessão atual.
     */
    public function loadCurrent(): Session
    {
        $rawToken = $this->getCookieToken();

        /*
         * Validação antes de consultar o banco.
         *
         * Evita queries desnecessárias para cookies obviamente
         * inválidos e reduz superfície para abuso de recursos.
         */
        if ($rawToken === null) {
            return $this;
        }

        $tokenHash = self::hashToken(
            $rawToken
        );

        /*
         * O banco contém somente o hash.
         */
        $this->load([
            'token = ?',
            $tokenHash,
        ]);

        if (
            !$this->id
            || !is_string($this->token)
            || $this->token === ''
        ) {
            self::clearBrowserCookie();

            return $this;
        }

        /*
         * Comparação constante para evitar diferenças de timing.
         */
        if (
            !hash_equals(
                $this->token,
                $tokenHash
            )
        ) {
            $this->invalidate();

            return $this;
        }

        /*
         * Sessão precisa estar ligada a um usuário válido.
         */
        $userId = self::validateUserId(
            $this->user_id
        );

        if ($userId === null) {
            $this->invalidate();

            return $this;
        }

        /*
         * Usuário excluído/desativado não pode continuar usando
         * uma sessão antiga.
         */
        if (!$this->isUserActive($userId)) {
            $this->invalidate();

            return $this;
        }

        $createdTimestamp =
            strtotime(
                (string) $this->created
            );

        if ($createdTimestamp === false) {
            $this->invalidate();

            return $this;
        }

        $now = time();

        /*
         * Timestamp futuro pode indicar corrupção/manipulação
         * de estado.
         */
        if ($createdTimestamp > ($now + 60)) {
            $this->invalidate();

            return $this;
        }

        $lifetime =
            self::sessionLifetime();

        $age =
            $now - $createdTimestamp;

        /*
         * Sessão expirada.
         */
        if (
            $age < 0
            || $age > $lifetime
        ) {
            $this->invalidate();

            return $this;
        }

        /*
         * Rotação periódica reduz a janela de reutilização de
         * um token eventualmente comprometido.
         */
        $rotationAge =
            max(
                300,
                intdiv(
                    $lifetime,
                    self::ROTATION_DIVISOR
                )
            );

        if ($age >= $rotationAge) {
            $this->rotateToken();
        }

        return $this;
    }

    /**
     * Define esta sessão como atual no navegador.
     */
    public function setCurrent(): Session
    {
        if (
            !$this->id
            || $this->rawToken === null
        ) {
            return $this;
        }

        if (
            !self::isValidRawToken(
                $this->rawToken
            )
        ) {
            throw new \RuntimeException(
                'Invalid session token.'
            );
        }

        self::sendCookie(
            $this->rawToken
        );

        return $this;
    }

    /**
     * Rotaciona o token da sessão.
     *
     * Útil contra session fixation e reduz o tempo útil de
     * tokens capturados.
     */
    public function rotateToken(): Session
    {
        if (!$this->id) {
            return $this;
        }

        $userId =
            self::validateUserId(
                $this->user_id
            );

        if (
            $userId === null
            || !$this->isUserActive($userId)
        ) {
            $this->invalidate();

            return $this;
        }

        $this->generateToken();

        $this->created =
            date('Y-m-d H:i:s');

        $this->ip =
            self::currentIp();

        parent::save();

        $this->setCurrent();

        return $this;
    }

    /**
     * Exclui a sessão.
     */
    public function delete(): Session
    {
        /*
         * Limpa o cookie somente quando esta instância representa
         * a sessão atualmente utilizada pelo navegador.
         *
         * Isso evita que a exclusão administrativa de outra sessão
         * derrube a sessão atual.
         */
        if ($this->isCurrentBrowserSession()) {
            self::clearBrowserCookie();
        }

        if ($this->id) {
            parent::delete();
        }

        $this->rawToken = null;

        return $this;
    }

    /**
     * Invalidação explícita de sessão comprometida, expirada
     * ou inconsistente.
     */
    public function invalidate(): Session
    {
        if ($this->isCurrentBrowserSession()) {
            self::clearBrowserCookie();
        }

        if ($this->id) {
            parent::delete();
        }

        $this->rawToken = null;

        return $this;
    }

    /**
     * Cria token criptograficamente seguro.
     */
    private function generateToken(): void
    {
        $rawToken =
            bin2hex(
                random_bytes(
                    self::TOKEN_BYTES
                )
            );

        if (
            !self::isValidRawToken(
                $rawToken
            )
        ) {
            throw new \RuntimeException(
                'Unable to create secure session token.'
            );
        }

        $this->rawToken =
            $rawToken;

        /*
         * Nunca persistimos o bearer token propriamente dito.
         */
        $this->token =
            self::hashToken(
                $rawToken
            );
    }

    /**
     * Obtém cookie somente se tiver exatamente o formato esperado.
     */
    private function getCookieToken(): ?string
    {
        $value =
            \Base::instance()
                ->get(
                    'COOKIE.'
                    . self::COOKIE_NAME
                );

        if (!is_string($value)) {
            return null;
        }

        $value = trim($value);

        if (
            !self::isValidRawToken(
                $value
            )
        ) {
            /*
             * Cookie malformado não deve permanecer sendo enviado
             * a cada requisição.
             */
            self::clearBrowserCookie();

            return null;
        }

        return $value;
    }

    /**
     * Token bruto = 32 bytes representados por 64 caracteres hex.
     */
    private static function isValidRawToken(
        string $token
    ): bool {
        return preg_match(
            '/\A[a-f0-9]{64}\z/D',
            $token
        ) === 1;
    }

    /**
     * Hash determinístico necessário para localizar a sessão.
     */
    private static function hashToken(
        string $token
    ): string {
        return hash(
            'sha256',
            $token
        );
    }

    /**
     * Confirma que o usuário associado continua ativo.
     */
    private function isUserActive(
        int $userId
    ): bool {
        $user = new User();

        $user->load([
            'id = ? AND deleted_date IS NULL',
            $userId,
        ]);

        return (bool) $user->id;
    }

    /**
     * Identifica se esta instância representa a sessão
     * atualmente enviada pelo navegador.
     */
    private function isCurrentBrowserSession(): bool
    {
        if (
            !is_string($this->token)
            || $this->token === ''
        ) {
            return false;
        }

        $rawToken =
            $this->getCookieToken();

        if ($rawToken === null) {
            return false;
        }

        $browserHash =
            self::hashToken(
                $rawToken
            );

        return hash_equals(
            $this->token,
            $browserHash
        );
    }

    /**
     * Validação rígida do identificador de usuário.
     */
    private static function validateUserId(
        mixed $value
    ): ?int {
        if (
            $value === null
            || $value === ''
            || is_bool($value)
        ) {
            return null;
        }

        $id =
            filter_var(
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
     * Limita o tempo de sessão para evitar erro de configuração
     * causando sessões praticamente permanentes.
     */
    private static function sessionLifetime(): int
    {
        $configured =
            (int) \Base::instance()
                ->get(
                    'session_lifetime'
                );

        if (
            $configured <= 0
            || $configured
                > self::MAX_LIFETIME
        ) {
            return self::DEFAULT_LIFETIME;
        }

        return $configured;
    }

    /**
     * IP é apenas dado auxiliar.
     *
     * Não fazemos bloqueio rígido por IP porque usuários móveis,
     * VPNs e proxies podem trocar de IP legitimamente.
     */
    private static function currentIp(): ?string
    {
        $ip =
            \Base::instance()
                ->get('IP');

        if (!is_string($ip)) {
            return null;
        }

        $ip = trim($ip);

        if (
            filter_var(
                $ip,
                FILTER_VALIDATE_IP
            ) === false
        ) {
            return null;
        }

        /*
         * Limite defensivo para o campo do banco.
         * IPv6 textual cabe confortavelmente.
         */
        if (strlen($ip) > 45) {
            return null;
        }

        return $ip;
    }

    /**
     * Envia cookie de autenticação com configurações seguras.
     */
    private static function sendCookie(
        string $token
    ): void {
        if (
            headers_sent()
            || !self::isValidRawToken(
                $token
            )
        ) {
            return;
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

                /*
                 * Em produção HTTPS isso deve ser true.
                 */
                'secure' =>
                    self::isHttps(),

                /*
                 * JavaScript não pode acessar o token.
                 */
                'httponly' =>
                    true,

                /*
                 * Lax protege contra vários cenários CSRF
                 * sem quebrar navegação normal.
                 */
                'samesite' =>
                    'Lax',
            ]
        );

        /*
         * Mantém o hive F3 coerente durante esta requisição.
         */
        \Base::instance()->set(
            'COOKIE.'
            . self::COOKIE_NAME,
            $token
        );
    }

    /**
     * Expira cookie de autenticação.
     */
    private static function clearBrowserCookie(): void
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

        \Base::instance()->clear(
            'COOKIE.'
            . self::COOKIE_NAME
        );
    }

    /**
     * Detecta HTTPS sem confiar diretamente em headers
     * Forwarded enviados pelo cliente.
     */
    private static function isHttps(): bool
    {
        $f3 =
            \Base::instance();

        $scheme =
            strtolower(
                trim(
                    (string) $f3->get(
                        'SCHEME'
                    )
                )
            );

        if ($scheme === 'https') {
            return true;
        }

        $https =
            strtolower(
                trim(
                    (string) $f3->get(
                        'SERVER.HTTPS'
                    )
                )
            );

        return in_array(
            $https,
            [
                'on',
                '1',
                'true',
            ],
            true
        );
    }
}
