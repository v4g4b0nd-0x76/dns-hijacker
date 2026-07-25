#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

export CARGO_PROFILE_RELEASE_OPT_LEVEL="${CARGO_PROFILE_RELEASE_OPT_LEVEL:-z}"
BASE_RUSTFLAGS="${RUSTFLAGS:-} -C llvm-args=--inline-threshold=275 -C strip=symbols"
export RUSTFLAGS="$BASE_RUSTFLAGS"

cmd="${1:-auto}"
bin="${2:-dns_hijacker}" # <-- which workspace binary to build; matches the
#     name registered in that crate's Cargo.toml

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
    echo "==> building release for $triple ($bin)"
    need_target "$triple"
    RUSTFLAGS="$BASE_RUSTFLAGS $extra_flags" \
        cargo build --bin "$bin" --release --target "$triple"
    local out="target/${triple}/release/${bin}"
    if [[ -f "$out" ]]; then
        echo "==> artifact: $out ($(du -h "$out" | awk '{print $1}'))"
        file "$out" || true
    fi
}

host_os="$(uname -s)"
host_arch="$(uname -m)"

case "$cmd" in
auto)
    if [[ "$host_os" == "Darwin" ]]; then
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
    echo "usage: $0 [auto|gnu|gnu-arm|musl|musl-arm|mac|all] [bin_name]" >&2
    exit 1
    ;;
esac
echo "==> done"
