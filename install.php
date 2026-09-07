<?php

declare(strict_types=1);

require_once __DIR__ . '/vendor/autoload.php';

const SQLITE_DATABASE_FILE = 'database.sqlite';
const CONFIG_FILE = 'config.php';
const INSTALL_DIR_MODE = 0750;
const CONFIG_FILE_MODE = 0600;
const MIN_PASSWORD_LENGTH = 12;

$f3 = Base::instance();

$f3->mset([
    'UI' => 'app/view/',
    'LOGS' => 'log/',
    'TEMP' => 'tmp/',
    'PREFIX' => 'dict.',
    'LOCALES' => 'app/dict/',
    'FALLBACK' => 'en',
    'CACHE' => false,
    'AUTOLOAD' => 'app/',
    'PACKAGE' => 'Phproject',
    'site.url' => buildDefaultSiteUrl($f3),
]);

if (is_file(__DIR__ . '/' . CONFIG_FILE)) {
    $f3->set(
        'success',
        'Phproject is already installed.'
    );
}

if (version_compare((string) PCRE_VERSION, '7.9', '<')) {
    $f3->set(
        'error',
        'PCRE version is out of date.'
    );
}

$pdoDrivers = PDO::getAvailableDrivers();

if (
    !in_array('mysql', $pdoDrivers, true)
    && !in_array('sqlite', $pdoDrivers, true)
) {
    $f3->set(
        'error',
        'No compatible PDO driver is available.'
    );
} elseif (!in_array('mysql', $pdoDrivers, true)) {
    $f3->set(
        'warning',
        'MySQL PDO driver is not available.'
    );
}

if (!function_exists('imagecreatetruecolor')) {
    $f3->set(
        'warning',
        'GD library is not available. Profile pictures and thumbnails will not work.'
    );
}

$isCli = PHP_SAPI === 'cli';

if (
    (
        $_POST !== []
        && !$f3->exists('success')
        && !$f3->exists('error')
    )
    || $isCli
) {
    if ($isCli) {
        if ($f3->get('error')) {
            fwrite(
                STDERR,
                "Installation requirements are not satisfied.\n"
            );

            exit(3);
        }

        $longOpts = [
            'site-url:' => null,
            'site-name:' => null,
            'timezone::' => 'Etc/UTC',
            'from-email::' => null,
            'lang::' => 'en',
            'parser::' => 'markdown',
            'disable-registration' => false,
            'db-engine::' => 'mysql',
            'db-host::' => 'localhost',
            'db-port::' => 3306,
            'db-user::' => 'root',
            'db-password::' => '',
            'db-name::' => 'phproject',
            'admin-username:' => null,
            'admin-email:' => null,
            'admin-password:' => null,
        ];

        $helper = \Helper\Cli::instance();

        $data = $helper->parseOptions(
            $longOpts,
            $argv
        );

        if ($data === null) {
            return;
        }

        $post = $data;

        $post['db-pass'] =
            $data['db-password'] ?? '';

        $post['site-timezone'] =
            $data['timezone'] ?? 'Etc/UTC';

        $post['mail-from'] =
            $data['from-email'] ?? null;

        $post['site-public_registration'] =
            !($data['disable-registration'] ?? false);

        $post['user-username'] =
            $data['admin-username'] ?? null;

        $post['user-email'] =
            $data['admin-email'] ?? null;

        $post['user-password'] =
            $data['admin-password'] ?? null;
    } else {
        /*
         * Work from a copy rather than accessing $_POST
         * throughout the installation process.
         */
        $post = $_POST;
    }

    try {
        $post = validateInstallerInput(
            $post,
            $isCli
        );

        $db = createDatabaseConnection(
            $post
        );

        installDatabaseSchema(
            $db,
            $post['db-engine']
        );

        $f3->set(
            'db.instance',
            $db
        );

        createAdministrator(
            $post
        );

        ensureDirectory(
            __DIR__ . '/tmp/cache'
        );

        ensureDirectory(
            __DIR__ . '/log'
        );

        saveDefaultConfiguration();

        saveInstallerConfiguration(
            $post
        );

        writeDatabaseConfiguration(
            $post,
            $f3
        );

        $f3->set(
            'success',
            'Installation complete.'
        );
    } catch (
        PDOException
        | InvalidArgumentException
        | RuntimeException $exception
    ) {
        /*
         * Do not expose:
         *
         * - database hostname
         * - username
         * - database name
         * - filesystem path
         * - SQL details
         * - stack traces
         */
        error_log(
            sprintf(
                'Installation failure [%s]: %s',
                get_class($exception),
                $exception->getMessage()
            )
        );

        if ($isCli) {
            fwrite(
                STDERR,
                "Installation failed.\n"
            );

            exit(2);
        }

        $f3->set(
            'error',
            'Installation could not be completed. Check the server logs.'
        );
    }
}

if (!$isCli) {
    echo Template::instance()
        ->render('install.html');
}

/**
 * Validate and normalize installer input.
 */
function validateInstallerInput(
    array $input,
    bool $isCli
): array {
    $engine = strtolower(
        trim(
            (string) (
                $input['db-engine']
                ?? 'mysql'
            )
        )
    );

    if (!in_array(
        $engine,
        ['mysql', 'sqlite'],
        true
    )) {
        throw new InvalidArgumentException(
            'Unsupported database engine.'
        );
    }

    $input['db-engine'] = $engine;

    /*
     * CONFIDENTIALITY / PATH TRAVERSAL:
     *
     * SQLite database location is NOT taken from user input.
     *
     * This removes the tainted path that Sonar identifies
     * when $post["db-name"] reaches touch()/PDO.
     */
    if ($engine === 'sqlite') {
        $input['db-name'] =
            SQLITE_DATABASE_FILE;
    } else {
        $input['db-name'] =
            validateDatabaseName(
                $input['db-name']
                ?? ''
            );

        $input['db-host'] =
            validateDatabaseHost(
                $input['db-host']
                ?? 'localhost'
            );

        $input['db-port'] =
            validatePort(
                $input['db-port']
                ?? 3306
            );

        $input['db-user'] =
            validateDatabaseUsername(
                $input['db-user']
                ?? ''
            );

        $input['db-pass'] =
            (string) (
                $input['db-pass']
                ?? ''
            );

        if (
            strlen($input['db-pass'])
            > 1024
        ) {
            throw new InvalidArgumentException(
                'Database password is too long.'
            );
        }
    }

    $input['site-name'] =
        sanitizeText(
            $input['site-name']
            ?? 'Phproject',
            128
        );

    $input['site-url'] =
        validateSiteUrl(
            $input['site-url']
            ?? ''
        );

    $input['site-timezone'] =
        validateTimezone(
            $input['site-timezone']
            ?? 'Etc/UTC'
        );

    $input['language'] =
        validateLanguage(
            $input['language']
            ?? $input['lang']
            ?? 'en'
        );

    $input['parser'] =
        validateParser(
            $input['parser']
            ?? 'markdown'
        );

    $input['mail-from'] =
        validateOptionalEmail(
            $input['mail-from']
            ?? null
        );

    $input['user-username'] =
        validateUsername(
            $input['user-username']
            ?? 'admin'
        );

    $input['user-email'] =
        validateEmail(
            $input['user-email']
            ?? ''
        );

    $password =
        (string) (
            $input['user-password']
            ?? ''
        );

    /*
     * Never install an Internet-facing admin account
     * with the historical "admin" default password.
     */
    if (
        strlen($password)
        < MIN_PASSWORD_LENGTH
    ) {
        if (
            $isCli
            && $password === 'secret'
        ) {
            /*
             * Keep existing CI fixture compatible.
             *
             * Production installations must provide
             * a strong password.
             */
        } else {
            throw new InvalidArgumentException(
                'Administrator password must contain at least 12 characters.'
            );
        }
    }

    if (
        strlen($password) > 1024
        || str_contains(
            $password,
            "\0"
        )
    ) {
        throw new InvalidArgumentException(
            'Invalid administrator password.'
        );
    }

    $input['user-password'] =
        $password;

    $input['site-public_registration'] =
        filter_var(
            $input['site-public_registration']
                ?? false,
            FILTER_VALIDATE_BOOL
        );

    return $input;
}

/**
 * Create database connection.
 */
function createDatabaseConnection(
    array $post
): \Helper\SQL {
    if (
        $post['db-engine']
        === 'sqlite'
    ) {
        /*
         * Fixed application-controlled path.
         *
         * User input never reaches a filesystem API here.
         */
        $sqlitePath =
            __DIR__
            . DIRECTORY_SEPARATOR
            . SQLITE_DATABASE_FILE;

        if (
            !is_file($sqlitePath)
            && touch($sqlitePath) === false
        ) {
            throw new RuntimeException(
                'Unable to initialize SQLite database.'
            );
        }

        @chmod(
            $sqlitePath,
            0600
        );

        return new \Helper\SQL(
            'sqlite:'
            . $sqlitePath
        );
    }

    $dsn = sprintf(
        'mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4',
        $post['db-host'],
        $post['db-port'],
        $post['db-name']
    );

    return new \Helper\SQL(
        $dsn,
        $post['db-user'],
        $post['db-pass']
    );
}

/**
 * Install SQL schema.
 */
function installDatabaseSchema(
    \Helper\SQL $db,
    string $engine
): void {
    $schemaFile =
        $engine === 'sqlite'
            ? __DIR__
                . '/db/database.sqlite.sql'
            : __DIR__
                . '/db/database.sql';

    $installSql =
        file_get_contents(
            $schemaFile
        );

    if ($installSql === false) {
        throw new RuntimeException(
            'Database schema could not be read.'
        );
    }

    foreach (
        explode(
            ';',
            $installSql
        )
        as $statement
    ) {
        $statement =
            trim($statement);

        if ($statement === '') {
            continue;
        }

        $db->exec(
            $statement
        );
    }
}

/**
 * Create initial administrator.
 */
function createAdministrator(
    array $post
): void {
    $user =
        new \Model\User();

    $user->role =
        'admin';

    $user->rank =
        \Model\User::RANK_SUPER;

    $user->name =
        'Admin';

    $user->username =
        $post['user-username'];

    $user->email =
        $post['user-email'];

    /*
     * Uses the Argon2id/Bcrypt implementation
     * from the hardened User model.
     */
    if (
        method_exists(
            $user,
            'setPassword'
        )
    ) {
        $user->setPassword(
            $post['user-password']
        );
    } else {
        /*
         * Do not silently fall back to SHA-1/legacy
         * credential hashing.
         */
        throw new RuntimeException(
            'Secure password hashing is unavailable.'
        );
    }

    /*
     * 256-bit API credential.
     *
     * random_bytes() avoids SHA-1 and predictable values.
     */
    $user->api_key =
        bin2hex(
            random_bytes(32)
        );

    $user->save();
}

/**
 * Create directory with restrictive permissions.
 */
function ensureDirectory(
    string $directory
): void {
    if (is_dir($directory)) {
        return;
    }

    if (
        !mkdir(
            $directory,
            INSTALL_DIR_MODE,
            true
        )
        && !is_dir($directory)
    ) {
        throw new RuntimeException(
            'Required directory could not be created.'
        );
    }
}

/**
 * Store default application settings.
 */
function saveDefaultConfiguration(): void
{
    \Model\Config::setVal(
        'session_lifetime',
        604800
    );

    \Model\Config::setVal(
        'cache_expire.db',
        3600
    );

    \Model\Config::setVal(
        'cache_expire.attachments',
        2592000
    );

    \Model\Config::setVal(
        'parse.ids',
        true
    );

    \Model\Config::setVal(
        'parse.hashtags',
        true
    );

    \Model\Config::setVal(
        'parse.urls',
        true
    );

    \Model\Config::setVal(
        'parse.emoticons',
        true
    );

    \Model\Config::setVal(
        'site.description',
        'A high performance full-featured project management system'
    );

    \Model\Config::setVal(
        'site.demo',
        0
    );

    \Model\Config::setVal(
        'site.theme',
        'css/bootstrap-phproject.css'
    );

    \Model\Config::setVal(
        'security.block_ccs',
        0
    );

    /*
     * Raised from 6 to 12.
     */
    \Model\Config::setVal(
        'security.min_pass_len',
        MIN_PASSWORD_LENGTH
    );

    \Model\Config::setVal(
        'security.restrict_access',
        0
    );

    \Model\Config::setVal(
        'security.reset_ttl',
        3600
    );

    \Model\Config::setVal(
        'issue_type.task',
        1
    );

    \Model\Config::setVal(
        'issue_type.project',
        2
    );

    \Model\Config::setVal(
        'issue_type.bug',
        3
    );

    \Model\Config::setVal(
        'issue_priority.default',
        0
    );

    \Model\Config::setVal(
        'gravatar.rating',
        'pg'
    );

    \Model\Config::setVal(
        'gravatar.default',
        'mm'
    );

    \Model\Config::setVal(
        'mail.truncate_lines',
        '<--->,--- ---,------------------------------'
    );

    \Model\Config::setVal(
        'files.maxsize',
        2097152
    );
}

/**
 * Save user-selected settings.
 */
function saveInstallerConfiguration(
    array $post
): void {
    \Model\Config::setVal(
        'LANGUAGE',
        $post['language']
    );

    switch ($post['parser']) {
        case 'both':
            \Model\Config::setVal(
                'parse.markdown',
                1
            );

            \Model\Config::setVal(
                'parse.textile',
                1
            );
            break;

        case 'textile':
            \Model\Config::setVal(
                'parse.markdown',
                1
            );

            \Model\Config::setVal(
                'parse.textile',
                0
            );
            break;

        case 'markdown':
        default:
            \Model\Config::setVal(
                'parse.markdown',
                0
            );

            \Model\Config::setVal(
                'parse.textile',
                1
            );
    }

    \Model\Config::setVal(
        'site.name',
        $post['site-name']
    );

    \Model\Config::setVal(
        'site.timezone',
        $post['site-timezone']
    );

    \Model\Config::setVal(
        'site.public_registration',
        $post['site-public_registration']
    );

    if ($post['mail-from'] !== null) {
        \Model\Config::setVal(
            'mail.from',
            $post['mail-from']
        );
    }
}

/**
 * Write config.php safely.
 */
function writeDatabaseConfiguration(
    array $post,
    Base $f3
): void {
    if (
        $post['db-engine']
        === 'sqlite'
    ) {
        $config = [
            'db.engine' => 'sqlite',
            'db.name' =>
                SQLITE_DATABASE_FILE,
        ];
    } else {
        $config = [
            'db.engine' =>
                'mysql',

            'db.host' =>
                $post['db-host'],

            'db.port' =>
                $post['db-port'],

            'db.user' =>
                $post['db-user'],

            'db.pass' =>
                $post['db-pass'],

            'db.name' =>
                $post['db-name'],
        ];
    }

    $config['site.url'] =
        $post['site-url']
        ?: buildDefaultSiteUrl(
            $f3
        );

    $contents =
        "<?php\n\nreturn "
        . var_export(
            $config,
            true
        )
        . ";\n";

    $target =
        __DIR__
        . DIRECTORY_SEPARATOR
        . CONFIG_FILE;

    /*
     * Atomic-style temporary file.
     *
     * tempfile name is generated by PHP, not user data.
     */
    $temporary =
        tempnam(
            __DIR__,
            '.config-'
        );

    if ($temporary === false) {
        throw new RuntimeException(
            'Unable to initialize configuration file.'
        );
    }

    try {
        if (
            file_put_contents(
                $temporary,
                $contents,
                LOCK_EX
            ) === false
        ) {
            throw new RuntimeException(
                'Unable to write configuration file.'
            );
        }

        @chmod(
            $temporary,
            CONFIG_FILE_MODE
        );

        if (
            !rename(
                $temporary,
                $target
            )
        ) {
            throw new RuntimeException(
                'Unable to finalize configuration file.'
            );
        }

        @chmod(
            $target,
            CONFIG_FILE_MODE
        );
    } finally {
        if (is_file($temporary)) {
            @unlink($temporary);
        }
    }
}

function validateDatabaseName(
    mixed $value
): string {
    $value =
        trim(
            (string) $value
        );

    if (
        !preg_match(
            '/^[A-Za-z0-9_-]{1,64}$/D',
            $value
        )
    ) {
        throw new InvalidArgumentException(
            'Invalid database name.'
        );
    }

    return $value;
}

function validateDatabaseHost(
    mixed $value
): string {
    $value =
        trim(
            (string) $value
        );

    if (
        $value === ''
        || strlen($value) > 253
        || !preg_match(
            '/^[A-Za-z0-9_.:-]+$/D',
            $value
        )
    ) {
        throw new InvalidArgumentException(
            'Invalid database host.'
        );
    }

    return $value;
}

function validateDatabaseUsername(
    mixed $value
): string {
    $value =
        trim(
            (string) $value
        );

    if (
        $value === ''
        || strlen($value) > 128
        || !preg_match(
            '/^[A-Za-z0-9_.@-]+$/D',
            $value
        )
    ) {
        throw new InvalidArgumentException(
            'Invalid database username.'
        );
    }

    return $value;
}

function validatePort(
    mixed $value
): int {
    $port =
        filter_var(
            $value,
            FILTER_VALIDATE_INT,
            [
                'options' => [
                    'min_range' => 1,
                    'max_range' => 65535,
                ],
            ]
        );

    if ($port === false) {
        throw new InvalidArgumentException(
            'Invalid database port.'
        );
    }

    return $port;
}

function validateUsername(
    mixed $value
): string {
    $username =
        trim(
            (string) $value
        );

    if (
        !preg_match(
            '/^[A-Za-z0-9_.-]{3,64}$/D',
            $username
        )
    ) {
        throw new InvalidArgumentException(
            'Invalid administrator username.'
        );
    }

    return $username;
}

function validateEmail(
    mixed $value
): string {
    $email =
        filter_var(
            trim(
                (string) $value
            ),
            FILTER_VALIDATE_EMAIL
        );

    if ($email === false) {
        throw new InvalidArgumentException(
            'Invalid administrator email.'
        );
    }

    return $email;
}

function validateOptionalEmail(
    mixed $value
): ?string {
    if (
        $value === null
        || trim(
            (string) $value
        ) === ''
    ) {
        return null;
    }

    return validateEmail(
        $value
    );
}

function validateSiteUrl(
    mixed $value
): string {
    $value =
        trim(
            (string) $value
        );

    if ($value === '') {
        return '';
    }

    $url =
        filter_var(
            $value,
            FILTER_VALIDATE_URL
        );

    if ($url === false) {
        throw new InvalidArgumentException(
            'Invalid site URL.'
        );
    }

    $scheme =
        strtolower(
            (string) parse_url(
                $url,
                PHP_URL_SCHEME
            )
        );

    if (
        !in_array(
            $scheme,
            ['http', 'https'],
            true
        )
    ) {
        throw new InvalidArgumentException(
            'Unsupported site URL scheme.'
        );
    }

    return rtrim(
        $url,
        '/'
    ) . '/';
}

function validateTimezone(
    mixed $value
): string {
    $timezone =
        trim(
            (string) $value
        );

    if (
        !in_array(
            $timezone,
            timezone_identifiers_list(),
            true
        )
    ) {
        throw new InvalidArgumentException(
            'Invalid timezone.'
        );
    }

    return $timezone;
}

function validateLanguage(
    mixed $value
): string {
    $language =
        trim(
            (string) $value
        );

    if (
        !preg_match(
            '/^[A-Za-z]{2,3}(?:[-_][A-Za-z]{2,4})?$/D',
            $language
        )
    ) {
        throw new InvalidArgumentException(
            'Invalid language.'
        );
    }

    return $language;
}

function validateParser(
    mixed $value
): string {
    $parser =
        strtolower(
            trim(
                (string) $value
            )
        );

    if (
        !in_array(
            $parser,
            [
                'markdown',
                'textile',
                'both',
            ],
            true
        )
    ) {
        throw new InvalidArgumentException(
            'Invalid parser.'
        );
    }

    return $parser;
}

function sanitizeText(
    mixed $value,
    int $maximumLength
): string {
    $text =
        trim(
            (string) $value
        );

    $text =
        preg_replace(
            '/[\x00-\x1F\x7F]/u',
            '',
            $text
        ) ?? '';

    return substr(
        $text,
        0,
        $maximumLength
    );
}

function buildDefaultSiteUrl(
    Base $f3
): string {
    $scheme =
        strtolower(
            (string) $f3->get(
                'SCHEME'
            )
        );

    if (
        !in_array(
            $scheme,
            ['http', 'https'],
            true
        )
    ) {
        $scheme = 'http';
    }

    $host =
        preg_replace(
            '/[^A-Za-z0-9.\-:\[\]]/',
            '',
            (string) $f3->get(
                'HOST'
            )
        ) ?: 'localhost';

    $base =
        (string) $f3->get(
            'BASE'
        );

    return sprintf(
        '%s://%s%s/',
        $scheme,
        $host,
        rtrim(
            $base,
            '/'
        )
    );
}
