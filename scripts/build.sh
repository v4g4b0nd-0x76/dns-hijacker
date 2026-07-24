#!/usr/bin/env bash
# Build size-optimized release binaries for Linux GNU, Linux musl, and macOS Apple Silicon (M4).
#
# Usage:
#   ./scripts/build.sh              # all targets that this host can build
#   ./scripts/build.sh gnu          # x86_64-unknown-linux-gnu
#   ./scripts/build.sh gnu-arm      # aarch64-unknown-linux-gnu
#   ./scripts/build.sh musl         # x86_64-unknown-linux-musl (static)
#   ./scripts/build.sh musl-arm     # aarch64-unknown-linux-musl (static)
#   ./scripts/build.sh mac          # aarch64-apple-darwin (Apple Silicon / M4)
#   ./scripts/build.sh all          # attempt every target
#
# Prerequisites:
#   rustup, cargo
#   musl:     rustup target add x86_64-unknown-linux-musl && apt install musl-tools
#             (or use https://github.com/cross-rs/cross)
#   mac:      build on an Apple Silicon Mac, or use osxcross / cargo zigbuild

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# Size-oriented flags; LTO/codegen are also set in Cargo.toml [profile.release].
# LLVM inline-threshold keeps hot #[inline(always)] paths aggressive under opt-level=z.
export CARGO_PROFILE_RELEASE_OPT_LEVEL="${CARGO_PROFILE_RELEASE_OPT_LEVEL:-z}"
BASE_RUSTFLAGS="${RUSTFLAGS:-} -C llvm-args=--inline-threshold=275 -C strip=symbols"
export RUSTFLAGS="$BASE_RUSTFLAGS"

need_target() {
    local triple="$1"
    if ! rustup target list --installed | grep -qx "$triple"; then
        echo "==> installing rustup target: $triple"
        rustup target add "$triple"
    fi
}

build_one() {
    local triple="$1"
    local extra_flags="${2:-}"

    echo "==> building release for $triple"
    need_target "$triple"

    RUSTFLAGS="$BASE_RUSTFLAGS $extra_flags" \
        cargo build --bin dns_hijacker --release --target "$triple"

    local out="target/${triple}/release/dns-hijacker"
    if [[ -f "$out" ]]; then
        echo "==> artifact: $out ($(du -h "$out" | awk '{print $1}'))"
        file "$out" || true
    fi
}

host_os="$(uname -s)"
host_arch="$(uname -m)"
cmd="${1:-auto}"

case "$cmd" in
auto)
    if [[ "$host_os" == "Darwin" ]]; then
        # Do not pass -C target-cpu=native: ring asserts CAPS_STATIC for the
        # generic aarch64-apple-darwin feature set and panics otherwise.
        build_one "aarch64-apple-darwin"
    elif [[ "$host_os" == "Linux" ]]; then
        if [[ "$host_arch" == "aarch64" || "$host_arch" == "arm64" ]]; then
            build_one "aarch64-unknown-linux-gnu" "-C target-cpu=native"
        else
            build_one "x86_64-unknown-linux-gnu" "-C target-cpu=native"
        fi
    else
        echo "unsupported host: $host_os / $host_arch" >&2
        exit 1
    fi
    ;;
gnu)
    build_one "x86_64-unknown-linux-gnu"
    ;;
gnu-arm)
    build_one "aarch64-unknown-linux-gnu"
    ;;
musl)
    build_one "x86_64-unknown-linux-musl" "-C target-feature=+crt-static"
    ;;
musl-arm)
    build_one "aarch64-unknown-linux-musl" "-C target-feature=+crt-static"
    ;;
mac | macos | m4)
    # Portable Apple Silicon binary (M1–M4). Avoid target-cpu=native — it breaks
    # ring's aarch64-apple-darwin compile-time CPU feature assertions on CI.
    build_one "aarch64-apple-darwin"
    ;;
all)
    build_one "x86_64-unknown-linux-gnu" || true
    build_one "aarch64-unknown-linux-gnu" || true
    build_one "x86_64-unknown-linux-musl" "-C target-feature=+crt-static" || true
    build_one "aarch64-unknown-linux-musl" "-C target-feature=+crt-static" || true
    build_one "aarch64-apple-darwin" || true
    ;;
*)
    echo "usage: $0 [auto|gnu|gnu-arm|musl|musl-arm|mac|all]" >&2
    exit 1
    ;;
esac

echo "==> done"
