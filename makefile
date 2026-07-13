.PHONY: build build-gnu build-musl build-mac test run caps

build:
	@./scripts/build.sh auto

build-gnu:
	@./scripts/build.sh gnu

build-musl:
	@./scripts/build.sh musl

build-mac:
	@./scripts/build.sh mac

test:
	@cargo test

run: build
	@./target/release/dns-hijacker 2>/dev/null || \
	  ./target/*/release/dns-hijacker

# Linux: allow binding :53 without root (alternative to systemd AmbientCapabilities)
caps:
	@sudo setcap cap_net_bind_service=+ep ./target/release/dns-hijacker
