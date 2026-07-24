.PHONY: build build-gnu build-musl build-mac test run caps patch minor major

# Which workspace binary to operate on. Override per-invocation, e.g.:
#   make build bin=resolver_proxy
#   make run bin=resolver_proxy
bin ?= dns_hijacker

build:
	@./scripts/build.sh auto $(bin)
build-gnu:
	@./scripts/build.sh gnu $(bin)
build-musl:
	@./scripts/build.sh musl $(bin)
build-mac:
	@./scripts/build.sh mac $(bin)
test:
	@cargo test --bin $(bin)
run: build
	@./target/release/$(bin) 2>/dev/null || \
	  ./target/*/release/$(bin)
# Linux: allow binding :53 without root (alternative to systemd AmbientCapabilities)
caps:
	@sudo setcap cap_net_bind_service=+ep ./target/release/$(bin)

# Semver bump: updates Cargo.toml, commits "chore: release vX.Y.Z" (triggers release.yml), tags vX.Y.Z
# Optional: PUSH=1 make patch  (also pushes commit + tag)
patch:
	@PUSH="$(PUSH)" ./scripts/bump.sh patch
minor:
	@PUSH="$(PUSH)" ./scripts/bump.sh minor
major:
	@PUSH="$(PUSH)" ./scripts/bump.sh major
