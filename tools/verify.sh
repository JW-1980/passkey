#!/usr/bin/env bash
#
# Runs every check of this repository that the machine has the tools for, and says at the end which
# ones passed, failed or did not run. Exit code 1 when a check failed.
#
#   tools/verify.sh
#
# Android needs ANDROID_HOME (or packages/android/local.properties). PHPStan needs
# vendor/bin/phpstan, or PHPSTAN=/path/to/phpstan.phar.

set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

passed=() ; failed=() ; skipped=()

run() { # name, directory, command...
    local name="$1" dir="$2"; shift 2
    echo "── ${name}"
    if (cd "${ROOT}/${dir}" && "$@"); then passed+=("${name}"); else failed+=("${name}"); fi
}
skip() { skipped+=("$1 — $2"); }

# PHP
if [[ -x packages/php/vendor/bin/phpunit ]]; then
    run "php: tests" packages/php vendor/bin/phpunit
    run "php: style" packages/php vendor/bin/pint --test
    if [[ -n "${PHPSTAN:-}" ]]; then
        run "php: static analysis" packages/php php "${PHPSTAN}" analyse --no-progress --memory-limit=1G
    elif [[ -x packages/php/vendor/bin/phpstan ]]; then
        run "php: static analysis" packages/php vendor/bin/phpstan analyse --no-progress --memory-limit=1G
    else
        skip "php: static analysis" "phpstan is not installed"
    fi
else
    skip "php" "run 'composer install' at the repository root"
fi

# JavaScript
if [[ -d packages/js/node_modules ]]; then
    run "js: types" packages/js npm run -s typecheck
    run "js: tests" packages/js npm test --silent
    run "js: build" packages/js npm run -s build
    run "js: example bundle" packages/js npm run -s build:example
else
    skip "js" "run 'npm install' in packages/js"
fi

# Rust
if command -v cargo >/dev/null; then
    run "rust: format" packages/desktop cargo fmt --check
    run "rust: lints" packages/desktop cargo clippy --all-targets -- -D warnings
    run "rust: tests" packages/desktop cargo test
    run "rust: example" packages/desktop cargo build --example handoff
else
    skip "rust" "cargo is not installed"
fi

# Android
if [[ -n "${ANDROID_HOME:-}" || -f packages/android/local.properties ]] && command -v gradle >/dev/null; then
    run "android: tests and build" packages/android gradle --no-daemon -q testDebugUnitTest assembleRelease
else
    skip "android" "needs gradle and an Android SDK (ANDROID_HOME)"
fi

# End to end
if [[ -f examples/plain-php/public/app.js && -x packages/php/vendor/bin/phpunit ]] \
    && node -e "require('playwright')" 2>/dev/null; then
    run "end to end" . node --test e2e/passkey.e2e.mjs
else
    skip "end to end" "needs the example bundle, the PHP dependencies and Playwright"
fi

echo
echo "Passed (${#passed[@]}):"; printf '  %s\n' "${passed[@]:-none}"
echo "Did not run (${#skipped[@]}):"; printf '  %s\n' "${skipped[@]:-none}"
echo "Failed (${#failed[@]}):"; printf '  %s\n' "${failed[@]:-none}"
[[ ${#failed[@]} -eq 0 ]]
