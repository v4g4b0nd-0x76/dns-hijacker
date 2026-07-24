# resolver_proxy

A tiny local bind that sits between your OS (or LAN) and the [`dns_hijacker`](../dns_hijacker/README.md) resolver you've deployed on a machine outside your network's filtering. It exists for one job: get a DNS query out to your resolver without a DPI box on the path being able to recognize it as DNS, rewrite it, or drop it.

You point your system's DNS at `resolver_proxy` (typically `127.0.0.1`) the same way you'd point it at any local resolver. `resolver_proxy` then re-packages each query using whichever **transport mode** you've configured, sends it to your `dns_hijacker` instance, and unwraps the reply the same way before handing it back.

## Why this exists

Some networks don't just block specific domains at the DNS layer — they run DPI boxes that watch outbound UDP/53 traffic and inject forged responses for domains on a blocklist (see the root project README for how this looks in practice). Pointing your OS at a resolver outside the country doesn't help if the query itself is still recognizable plaintext DNS crossing the border — the DPI box forges the answer regardless of which IP you asked. `resolver_proxy` addresses this by changing _what the query looks like on the wire_, not just where it's sent.

## Transport modes

`resolver_proxy` supports three modes per upstream target. You choose per-instance, and can run several instances side by side (e.g. a primary obfuscated transport with a plain fallback for use on unfiltered networks).

### 1. `plain`

Forwards the query exactly as received — a normal DNS packet, sent as-is over UDP (or TCP, if configured) to the target. No obfuscation, no extra encryption beyond what the target itself provides.

Use this when:

- You're testing the pipeline end-to-end before adding obfuscation.
- You're on a network that doesn't do DNS injection/tampering, and you just want the drop/redirect/cache behavior of `dns_hijacker` without extra overhead.
- Your target is already something that handles its own transport security (e.g. you're pointing `plain` mode at a DoH URL, in which case the "plain" query rides inside the HTTPS request the same as it always would).

`plain` is the mode with no protection against DPI injection — if the network path forges responses to raw UDP/53, `plain` mode won't stop that. It's a baseline/fallback, not a circumvention mode.

### 2. `udp_obfs`

Wraps the DNS query as an encrypted, padded UDP datagram with no recognizable header or fixed size — the goal is that a DPI box sees an opaque blob it can't identify as DNS, rather than a smaller/cleverly-shaped DNS packet it can still parse.

Wire format, all of it inside one UDP datagram:

```
[ 12-byte random nonce ][ AEAD ciphertext of: 2-byte length prefix || real DNS query || random padding ]
```

- Encryption is ChaCha20-Poly1305 with a key shared out-of-band between `resolver_proxy` and `dns_hijacker` (generated with the shared lib's key-gen helper — see [Shared lib](#shared-lib) below).
- The plaintext that gets encrypted is a 2-byte big-endian length prefix, the actual DNS query bytes, and then random padding out to a randomized total size — padding is _inside_ the AEAD envelope, not appended after it, so the ciphertext's own length doesn't leak the real query's length to an observer doing size-based traffic analysis.
- `dns_hijacker` decrypts the datagram, reads the length prefix, keeps exactly that many bytes as the real query, and discards the rest as padding.
- Every packet gets a fresh nonce and a randomized padding bucket, so there's no fixed packet size or repeating byte pattern for DPI to key on.
- If decryption/tag verification fails (garbage, replay, active probing), `dns_hijacker` drops the packet silently — it never sends an error back to an unauthenticated sender, so a probing scanner gets nothing to fingerprint.

Use this when:

- Your network blocks or tampers with plaintext UDP/53 specifically, but doesn't do deep statistical fingerprinting of arbitrary UDP traffic.
- You want the lowest-latency option that still evades content-based DNS injection (no TLS handshake overhead).

Trade-off: a UDP blob to a non-standard port can itself look unusual on networks that whitelist known protocols rather than blocklist known-bad ones. If that's your situation, prefer `tls`.

### 3. `tls`

Wraps the same encrypted payload described above inside an actual TLS connection to the target, so what crosses the network is a real TLS handshake followed by an encrypted stream — indistinguishable at the protocol level from any other HTTPS-like traffic to that IP or domain.

- The inner payload (nonce + AEAD ciphertext + padding) is unchanged from `udp_obfs` — `tls` mode is the same framing, just carried over a TLS byte stream instead of a raw UDP datagram, giving you an additional layer of cover (a recognizable TLS ClientHello/handshake instead of a UDP packet).
- Supports connecting by **domain name** (SNI-based, so it looks like a normal TLS connection to that hostname) or by **raw `ip:port`** (no SNI, or a decoy SNI — see `sni_override` below).
- Because it's a real TLS session, this is the mode least likely to be blocked by protocol-allowlisting DPI, at the cost of the extra handshake round-trip on a fresh connection (subsequent queries on an already-open connection don't pay this cost again — `resolver_proxy` keeps the TLS session alive and reuses it).

Use this when:

- `udp_obfs` traffic gets blocked or throttled on your network (e.g. UDP to non-standard ports is itself suspicious).
- You want your traffic to blend in as ordinary HTTPS to a specific domain.

## Configuring a target: `ip:port` or domain

Each upstream target in `resolver_proxy`'s config can be given as either a bare `ip:port` or a domain name — which one you use interacts with the transport mode:

- **`plain` / `udp_obfs`**: target is almost always `ip:port`, since there's no TLS handshake to justify a hostname. A domain is still accepted and resolved once at startup (using the resolvers you already trust), but it adds no obfuscation benefit in these two modes.
- **`tls`**: target is usually a **domain**, so the TLS handshake's SNI is a real, resolvable hostname pointing at your `dns_hijacker` box — this is what makes the connection look like an ordinary HTTPS visit to that domain rather than a bare-IP TLS connection (which is itself a mild anomaly signal on some networks). You can still target a bare `ip:port` in `tls` mode; in that case either omit SNI entirely or set `sni_override` to a plausible unrelated hostname sharing that IP (only meaningful if your TLS termination in front of `dns_hijacker` is actually configured to answer for that name).

## Config format

```toml
[[targets]]
name = "primary"
mode = "udp_obfs"
address = "1.2.3.4:8853"        # ip:port
shared_key = "<base64 key, from shared lib key-gen>"
pad_min = 96
pad_max = 256

[[targets]]
name = "tls_fallback"
mode = "tls"
address = "resolver.example.com:443"   # domain — used as TLS SNI
shared_key = "<base64 key, same value as above or a different per-target key>"
# sni_override = "unrelated-looking-domain.com"   # optional, only for ip:port targets

[[targets]]
name = "unfiltered_fallback"
mode = "plain"
address = "1.1.1.1:53"
```

`resolver_proxy` tries targets in order (or round-robins, depending on your `strategy` setting — see below), so a typical setup is one `udp_obfs` or `tls` target as primary with a `plain` target as a last-resort fallback for networks where obfuscation isn't needed or is itself failing.

```toml
strategy = "ordered"   # "ordered" (try in list order, fail over) or "round_robin"
health_check_interval = 30   # seconds; unhealthy targets are skipped until they recover
```

## Shared lib

The AEAD framing (nonce generation, length-prefix encoding, padding, encrypt/decrypt) lives in the workspace's shared lib crate so `resolver_proxy` and `dns_hijacker` can't drift out of sync on wire format — both binaries link the same encode/decode functions. The shared lib also exposes the key-generation CLI helper used to produce `shared_key` values:

```bash
cargo run -p shared_lib --bin keygen
```

Copy the printed base64 key into the matching `[[targets]]` entry on the `resolver_proxy` side and the corresponding upstream listener entry on the `dns_hijacker` side — the key must match exactly on both ends for a given target/listener pair.

## How a query flows end to end

1. Your OS sends a normal DNS query to `resolver_proxy` on `127.0.0.1:53`.
2. `resolver_proxy` picks a target per `strategy`, encodes the query according to that target's `mode`, and sends it out (UDP datagram, or over an open/newly-opened TLS connection).
3. `dns_hijacker`, listening on the other end, decodes the packet back into a plain DNS query, runs it through its normal drop-list / redirect-list / cache / upstream-resolver pipeline exactly as it would for a directly-received query.
4. `dns_hijacker` encodes the answer the same way (fresh nonce, fresh padding) and sends it back.
5. `resolver_proxy` decodes the reply and returns it to your OS with the original transaction ID.

## Deployment notes

- `resolver_proxy` runs on the machine on the filtered network (your laptop, a home router, etc.) and needs no elevated privileges beyond binding to local port 53 the same way `dns_hijacker` does (`setcap`/`sudo`, see the main resolver's README).
- `dns_hijacker` runs on the machine outside the filtering, listening for whichever transport modes you've enabled — it must have a corresponding listener configured for each mode/target you point `resolver_proxy` at.
- Rotate `shared_key` values periodically, and treat any target whose address becomes publicly associated with this use as burned — move it to a new IP/domain rather than trying to keep using a known one.

### Notes

- Tested manually against the paired `dns_hijacker` instance; exact flag/config field names may vary slightly by build — check `--help` and the shared lib's config struct for the authoritative list.
- Bug reports and feature suggestions are welcome.
