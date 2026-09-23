#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

find src tests config -type f -name '*.php' -print0 \
    | xargs -0 -n1 php -l
php -l bin/loguard-spool-worker
composer validate --strict
composer install --no-interaction --prefer-dist
composer test
composer phpstan

printf '%s\n' 'LoGuard PHP SDK verification passed.'
