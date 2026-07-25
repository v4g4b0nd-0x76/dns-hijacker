# dns-hijacker

This project is made of three components:

- [The main resolver](./dns_hijacker/README.md)
- [The proxy resolver](./resolver_proxy/README.md)
- Shared lib

**The main resolver** is what you send your DNS queries to; it resolves them using your chosen upstream resolver(s), with support for drop lists, redirect lists, and caching.

**The proxy resolver** exists to bypass DPI DNS boxes that return whatever address they want for filtered domains. You deploy it on your own machine, point your DNS queries at it, and it builds an obfuscated UDP or TCP packet (depending on your configured transport) and sends it to your `dns_hijacker` instance. `dns_hijacker` decodes the packet, resolves the real address, encodes the answer the same way, and sends it back to you.

### Notes

- Tested manually on both Linux and macOS; no guarantee everything works identically on every setup.
- Bug reports and feature suggestions are welcome.

### Make file usages

```bash
# --- dns_hijacker (default bin, no need to pass bin=) ---

make build                     # auto-detect host target, build dns_hijacker
make build-gnu                 # x86_64-unknown-linux-gnu, dns_hijacker
make build-musl                # static musl build, dns_hijacker
make build-mac                 # aarch64-apple-darwin, dns_hijacker
make test                       # cargo test --bin dns_hijacker
make run                        # build then run dns_hijacker
make caps                       # setcap on dns_hijacker binary


# --- resolver_proxy (explicit bin=) ---

make build bin=resolver_proxy
make build-gnu bin=resolver_proxy
make build-musl bin=resolver_proxy
make build-mac bin=resolver_proxy
make test bin=resolver_proxy
make run bin=resolver_proxy
make caps bin=resolver_proxy


# --- direct script usage (bypassing make) ---

./scripts/build.sh auto dns_hijacker
./scripts/build.sh gnu resolver_proxy
./scripts/build.sh musl resolver_proxy
./scripts/build.sh mac resolver_proxy
./scripts/build.sh all resolver_proxy   # attempt every target for resolver_proxy


# --- version bump / release (unaffected by bin=, these are workspace-wide) ---

make patch                      # bump patch version, commit + tag locally
make minor
make major
make patch PUSH=1               # bump + push commit and tag to origin

```
