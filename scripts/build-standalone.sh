#!/usr/bin/env sh

set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=${1:-}

if [ -z "$version" ]; then
    echo "Usage: $0 VERSION" >&2
    exit 2
fi

if ! printf '%s' "$version" |
    grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9][A-Za-z0-9.-]*)?$'
then
    echo "Invalid standalone version: $version" >&2
    exit 2
fi

for command_name in php zip; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "Required build command not found: $command_name" >&2
        exit 2
    fi
done

package="loguard-php-sdk-$version"
dist="$root/dist"
temporary=$(mktemp -d)

cleanup() {
    rm -rf "$temporary"
}

trap cleanup EXIT INT TERM

stage="$temporary/$package"

mkdir -p "$stage/bin"
mkdir -p "$dist"

cp -R "$root/src" "$stage/src"
cp "$root/standalone/autoload.php" "$stage/autoload.php"
cp "$root/bin/loguard-spool-worker" "$stage/bin/loguard-spool-worker"
cp "$root/LICENSE" "$stage/LICENSE"
cp "$root/docs/STANDALONE.md" "$stage/README.md"
printf '%s\n' "$version" > "$stage/VERSION"

find "$stage" -type f -exec chmod 0644 {} \;
chmod 0755 "$stage/bin/loguard-spool-worker"

archive="$dist/$package.zip"
checksum="$archive.sha256"

rm -f "$archive" "$checksum"

(
    cd "$temporary"
    zip -X -q -r "$archive" "$package"
)

php -r '
$archive = $argv[1];
$checksum = $argv[2];
$hash = hash_file("sha256", $archive);

if ($hash === false) {
    fwrite(STDERR, "Unable to hash standalone archive\n");
    exit(1);
}

$result = file_put_contents(
    $checksum,
    $hash . "  " . basename($archive) . PHP_EOL
);

if ($result === false) {
    fwrite(STDERR, "Unable to write standalone checksum\n");
    exit(1);
}
' "$archive" "$checksum"

printf 'Built: %s\n' "$archive"
printf 'SHA-256: %s\n' "$checksum"
