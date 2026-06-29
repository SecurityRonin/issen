# RapidTriage dev commands.
#
# Cross-repo commands assume the parser repos live at ../repo relative to
# this workspace — the standard layout when following CLAUDE.md.
#
# Install: brew install just
# Usage:   just <recipe>

set shell := ["bash", "-c"]

# Parser repos that RapidTriage depends on, in dependency order
parser_repos := "forensicnomicon memory-forensic winevt-forensic srum-forensic browser-forensic"

# ── Single-repo commands ─────────────────────────────────────────────────────

# First-time setup: enable the repo's git hooks (fmt + clippy pre-commit).
# Without this, .githooks/pre-commit is never invoked and formatting can drift
# into main unnoticed.
setup:
    git config core.hooksPath .githooks
    @echo "git hooks enabled (core.hooksPath = .githooks)"

# Default: test this workspace
test:
    cargo test --workspace

# Clippy this workspace
clippy:
    cargo clippy --workspace -- -D warnings

# Format check this workspace
fmt:
    cargo fmt --all --check

# ── Cross-repo commands ──────────────────────────────────────────────────────

# Test all parser repos then RapidTriage (sequential — avoids OOM)
test-all:
    #!/usr/bin/env bash
    set -euo pipefail
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    for repo in {{parser_repos}}; do
        dir="$SCRIPT_DIR/../$repo"
        if [ -d "$dir" ]; then
            echo "=== cargo test --workspace ($repo) ==="
            cargo test --workspace --manifest-path "$dir/Cargo.toml"
        else
            echo "=== SKIP $repo (not found at $dir) ==="
        fi
    done
    echo "=== cargo test --workspace (RapidTriage) ==="
    cargo test --workspace
    echo "=== ALL PASS ==="

# Clippy all repos
clippy-all:
    #!/usr/bin/env bash
    set -euo pipefail
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    for repo in {{parser_repos}}; do
        dir="$SCRIPT_DIR/../$repo"
        if [ -d "$dir" ]; then
            echo "=== clippy ($repo) ==="
            cargo clippy --workspace --manifest-path "$dir/Cargo.toml" -- -D warnings
        fi
    done
    echo "=== clippy (RapidTriage) ==="
    cargo clippy --workspace -- -D warnings
    echo "=== ALL CLEAN ==="

# Print recent git log + dirty status across all repos
status:
    #!/usr/bin/env bash
    SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
    for repo in {{parser_repos}} RapidTriage; do
        dir="$SCRIPT_DIR/../$repo"
        [ "$repo" = "RapidTriage" ] && dir="$SCRIPT_DIR"
        if [ -d "$dir" ]; then
            echo "=== $repo ==="
            git -C "$dir" log --oneline -3
            git -C "$dir" status --short
            echo
        fi
    done
