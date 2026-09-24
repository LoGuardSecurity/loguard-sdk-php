<?php

declare(strict_types=1);

/**
 * LoGuard PHP SDK standalone autoloader.
 *
 * Composer remains the preferred installation method. This autoloader is for
 * controlled environments where Composer packages cannot be installed.
 */
spl_autoload_register(static function (string $class): void {
    $prefix = 'LoGuard\\Sdk\\';

    if (strncmp($class, $prefix, strlen($prefix)) !== 0) {
        return;
    }

    $relative = substr($class, strlen($prefix));

    if (
        $relative === ''
        || preg_match(
            '/\A[A-Za-z_][A-Za-z0-9_]*(?:\\\\[A-Za-z_][A-Za-z0-9_]*)*\z/D',
            $relative
        ) !== 1
    ) {
        return;
    }

    $path = __DIR__ . '/src/' . str_replace('\\', '/', $relative) . '.php';

    if (is_file($path)) {
        require $path;
    }
});

return true;
