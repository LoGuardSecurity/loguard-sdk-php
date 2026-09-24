#!/usr/bin/env sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version="0.0.0-test"
package="loguard-php-sdk-$version"
archive="$root/dist/$package.zip"
checksum="$archive.sha256"
temporary=$(mktemp -d)

cleanup() {
    rm -rf "$temporary"
    rm -f "$archive" "$checksum"
}

trap cleanup EXIT INT TERM

for command_name in php unzip; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "Required test command not found: $command_name" >&2
        exit 2
    fi
done

"$root/scripts/build-standalone.sh" "$version"

php -r '
$archive = $argv[1];
$checksumPath = $argv[2];
$line = trim((string) file_get_contents($checksumPath));
$expected = strtok($line, " ");
$actual = hash_file("sha256", $archive);

if (
    !is_string($expected)
    || !is_string($actual)
    || !hash_equals($expected, $actual)
) {
    fwrite(STDERR, "Standalone checksum verification failed\n");
    exit(1);
}

echo "Standalone checksum: PASS\n";
' "$archive" "$checksum"

unzip -q "$archive" -d "$temporary"

install_root="$temporary/$package"

for required in \
    autoload.php \
    src/Client.php \
    src/Config.php \
    src/CodeIgniter3/LoGuardHook.php \
    bin/loguard-spool-worker \
    LICENSE \
    README.md \
    VERSION
do
    if [ ! -f "$install_root/$required" ]; then
        echo "Missing standalone file: $required" >&2
        exit 1
    fi
done

if [ ! -x "$install_root/bin/loguard-spool-worker" ]; then
    echo "Standalone spool worker is not executable" >&2
    exit 1
fi

for forbidden in \
    vendor \
    tests \
    .git \
    .env \
    composer.json \
    composer.lock
do
    if [ -e "$install_root/$forbidden" ]; then
        echo "Forbidden standalone content present: $forbidden" >&2
        exit 1
    fi
done

if find "$install_root" -type l | grep -q .; then
    echo "Standalone archive contains symbolic links" >&2
    exit 1
fi

if [ "$(cat "$install_root/VERSION")" != "$version" ]; then
    echo "Standalone VERSION mismatch" >&2
    exit 1
fi

php -r '
require $argv[1] . "/autoload.php";

$classes = [
    LoGuard\Sdk\Client::class,
    LoGuard\Sdk\Config::class,
    LoGuard\Sdk\Event::class,
    LoGuard\Sdk\Signing::class,
    LoGuard\Sdk\Dispatch\FileSpool::class,
    LoGuard\Sdk\CodeIgniter3\LoGuardHook::class,
];

foreach ($classes as $class) {
    if (!class_exists($class)) {
        fwrite(
            STDERR,
            "Standalone class could not be loaded: {$class}\n"
        );
        exit(1);
    }
}

echo "Standalone class autoload: PASS\n";
' "$install_root"

set +e

worker_output=$(
    LOGUARD_API_KEY='' \
    php "$install_root/bin/loguard-spool-worker" 2>&1
)

worker_result=$?

set -e

if printf '%s\n' "$worker_output" |
    grep -q 'autoload file not found'
then
    printf '%s\n' "$worker_output" >&2
    echo "Standalone worker incorrectly requires Composer" >&2
    exit 1
fi

if ! printf '%s\n' "$worker_output" |
    grep -q 'api_key is required'
then
    printf '%s\n' "$worker_output" >&2
    echo "Unexpected standalone worker result: $worker_result" >&2
    exit 1
fi

echo "Standalone spool worker autoload: PASS"
echo "Standalone archive contents: PASS"
