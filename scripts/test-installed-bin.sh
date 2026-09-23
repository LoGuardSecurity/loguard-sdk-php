#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
consumer=$(mktemp -d)

cleanup() {
    rm -rf "$consumer"
}
trap cleanup EXIT INT TERM

php -r '
$root = $argv[1];
$target = $argv[2];

file_put_contents($target, json_encode([
    "repositories" => [[
        "type" => "path",
        "url" => $root,
        "options" => ["symlink" => false],
    ]],
    "require" => [
        "loguard/loguard-sdk" => "*",
    ],
    "minimum-stability" => "dev",
    "prefer-stable" => true,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . PHP_EOL);
' "$root" "$consumer/composer.json"

composer install \
    --working-dir="$consumer" \
    --no-dev \
    --no-interaction \
    --no-progress

set +e
output=$(
    LOGUARD_API_KEY='' \
    php "$consumer/vendor/bin/loguard-spool-worker" 2>&1
)
result=$?
set -e

if printf '%s\n' "$output" | grep -q 'Composer autoload file not found'; then
    printf '%s\n' "$output" >&2
    echo 'Installed Composer binary could not load autoload.php' >&2
    exit 1
fi

if ! printf '%s\n' "$output" | grep -q 'api_key is required'; then
    printf '%s\n' "$output" >&2
    echo "Unexpected installed binary result (exit $result)" >&2
    exit 1
fi

echo 'Composer-installed spool worker autoload: PASS'
