.PHONY: build build-gnu build-musl build-mac test run caps patch minor major

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

# Semver bump: updates Cargo.toml, commits "chore: release vX.Y.Z" (triggers release.yml), tags vX.Y.Z
# Optional: PUSH=1 make patch  (also pushes commit + tag)
patch:
	@PUSH="$(PUSH)" ./scripts/bump.sh patch

minor:
	@PUSH="$(PUSH)" ./scripts/bump.sh minor

major:
	@PUSH="$(PUSH)" ./scripts/bump.sh major
