# silk

A minimal transparent proxy built on the honk/dae kernel datapath design:
eBPF steers traffic in the kernel, **direct traffic never reaches
userspace** — only flows the kernel verdicts to a node enter this process,
which relays them through the named node the verdict selects (SOCKS5,
Hysteria2 or VLESS).

Reuses honk's architecture (veth-pair proxy netns, TC hooks, sk_lookup,
DNS-derived per-IP domain routing) with a drastically trimmed map surface
(7 maps instead of 40+) and a small, single-binary userspace.

## Layout

```
silk-ebpf-common/   shared kernel<->userspace ABI (no_std)
silk-ebpf/          eBPF programs (aya-ebpf, standalone crate)
silk/         userspace: loader, netns, listeners, nodes (SOCKS5/Hysteria2/VLESS), DNS engine
```

### eBPF programs (4 + sk_lookup)

| Program              | Hook                      | Role |
|----------------------|---------------------------|------|
| `lan_ingress`        | TC ingress, LAN iface     | gateway capture |
| `wan_egress`         | TC egress, WAN iface      | host-originated capture |
| `silk0peer_ingress`   | TC ingress, silk0peer      | restore skb mark inside `silkns` |
| `silk0_ingress`       | TC ingress, silk0          | restore reply framing, TX back |
| `sk_lookup`          | netns `silkns`             | assign conns to transparent listeners |

### Maps

`FLOW_TRACK` (reply framing) · `DOMAIN_ROUTE` (per-IP verdicts from DNS) ·
`CIDR_V4/V6` (LPM) · `PORT_ROUTE` · `LISTEN_SOCKETS` (sockmap) ·
`SK_IDENTITY` (sk_storage loop-prevention) · `PARAM` (global config).

### Routing decision (kernel, first match wins)

1. DNS hijack — UDP dport 53 → userspace DNS engine
2. `DOMAIN_ROUTE` — per-IP verdict published by the DNS engine
3. CIDR longest-prefix match
4. Port table
5. `general.default`

A verdict is `direct`, `block` or a **node name**. `direct` → `TC_ACT_OK`
and `block` → dropped, both entirely in the kernel. A node name is encoded as
`VERDICT_NODE_BASE + index` (index in the `nodes` list): the flow is marked,
recorded in `FLOW_TRACK` (with that verdict) and redirected into the `silkns`
proxy namespace, where sk_lookup hands it to the transparent listeners in
this process. Userspace reads the verdict back from `FLOW_TRACK` to pick the
node, so no outbound is hard-wired.

### Domain routing

eBPF never inspects domain strings. The DNS engine matches domain rules
against queried names, then publishes a verdict for **every IP** in the
answer into `DOMAIN_ROUTE`. Subsequent data packets to those IPs route by
domain — dae's trick, simplified.

### Loop prevention

Every outbound control-plane socket (SOCKS5 dial, Hysteria2 QUIC endpoint,
DNS upstream) is marked with `SO_MARK` (visible as `skb->mark`) *and*
carries an sk_storage flag; `wan_egress` passes sockets carrying either.

## Sniffing & dial-by-domain

Proxied TCP flows arrive as bare IPs. `sniff:` (on by default) peeks at the
client's first bytes (up to 4 KiB, 300 ms window) for a TLS SNI or HTTP
`Host`, then:

- re-runs the domain rules on it: `direct` is dialled locally (control-plane
  marked), `block` is dropped, a node name overrides the node the kernel
  chose;
- dials the proxy exit by name (SOCKS5 ATYP 3 / Hysteria2 `host:port`), so the
  exit resolves it itself.

Without a sniffed name, the DNS engine's IP→domain memory is used, but only
when the address maps to exactly one live name. Servers that speak first
(SSH, SMTP) are probed at most three times per destination, then skipped for
ten minutes.

**QUIC.** `sniff.enable` covers UDP too: the first datagram of every new
proxied UDP flow is checked for a QUIC Initial (v1, v2, draft-29); its SNI is
decrypted and handled like a TCP SNI: domain rules are re-run (`block` drops
the flow, `direct` is relayed from a control-plane socket in userspace, a node
name overrides the kernel's node) and the exit is dialled by name (SOCKS5
ATYP 3, Hysteria2 `host:port`, VLESS domain address). Only a name read from
the packet itself is used for UDP; the DNS IP→domain memory is not. Only the
first datagram is inspected, so a ClientHello split across two Initials
(Chrome with post-quantum key shares) is sniffed only when the SNI lies in the
first part.

## DNS upstreams

`dns.upstream` (domestic, queried directly) and `dns.remote` (overseas, queried
through a proxy node) take a URL; the scheme picks the transport and each has a
default port, so a port is only written when it differs:

| spelling | transport | default port |
|---|---|---|
| `223.5.5.5`, `udp://223.5.5.5` | UDP (scheme optional) | 53 |
| `tcp://223.5.5.5` | TCP | 53 |
| `tls://223.5.5.5` | DNS-over-TLS | 853 |
| `https://223.5.5.5/dns-query` | DNS-over-HTTPS | 443 |

`tls://dns.alidns.com:8853`, `udp://223.5.5.5:5353` and IPv6 (`2606:4700::1111`,
`[2606:4700::1111]:5353`) work too; the DoH path defaults to `/dns-query`. Only
UDP may omit the scheme.

- Direct queries use control-plane marked sockets, so silk never captures its
  own resolver traffic. Proxied queries (`dns.remote`) use the node's UDP relay
  for `udp://` and a proxied TCP stream for `tcp://`, `tls://` and `https://`.
- `dns.default` (e.g. `223.5.5.5`) resolves every *hostname* silk itself needs:
  node `server:` domains and DNS upstreams written as domains
  (`tls://dns.alidns.com`). It must be a plain UDP/TCP resolver given as an IP
  (`223.5.5.5`, `223.5.5.5:5353`, `tcp://223.5.5.5`). If unset it falls back to
  `dns.upstream` when that qualifies; node server names then go to the system
  resolver otherwise. Upstreams and node servers written as IPs need no
  resolver, and startup fails with a clear message when a DNS upstream hostname
  has none. Node servers are resolved before the eBPF hooks attach (a failing
  `dns.default` falls back to the system resolver with a warning); later
  lookups use marked sockets. Answers are cached for 5 minutes and dropped when
  an exchange fails.
- Certificates are verified against the bundled web PKI roots (an IP upstream
  needs an IP SAN, which the big public resolvers have).
- A UDP answer with the TC bit is retried over TCP on the same server. Each
  query opens a fresh connection (no keep-alive / session reuse yet); the DNS
  cache absorbs most of the handshake cost.

## Persistent state (`dns.store`)

`dns.store` names a [redb](https://github.com/cberner/redb) file that keeps two
things across restarts: the fake-IP mappings and the DNS response cache. Both
are served from memory; changes are written back in one transaction every 30 s
and once more at shutdown, so a hard kill loses at most the last 30 s. On
startup the cache is reloaded with its remaining TTLs and every restored
answer's domain verdict is **published to the kernel again from the current
rules** (the kernel maps are empty after a restart); entries that would now be
blocked or answered with a fake address are dropped. A different `fakeip.range`
discards the stored mappings. If the file cannot be opened (locked by another
silk, unwritable path), silk logs a warning and runs memory-only.

## Fake-IP

`dns.fakeip` (off by default) makes the DNS engine answer `A` queries for
names whose effective verdict is a **node** (a matching rule, else
`general.default`) with an address from `range` (default `198.18.0.0/15`)
instead of a real one. The range is routed to userspace by a kernel CIDR
entry; the relay maps the destination back to the domain, re-runs the rules
on it (the rule's node overrides the kernel's), and dials the exit by name —
TCP and UDP alike, so QUIC and protocols without SNI route by domain too, and
no remote DNS round-trip delays the first packet.

- `direct` / `block` domains are never faked: they resolve normally (or get
  NXDOMAIN), so direct traffic still never reaches userspace.
- IPv6 is opt-in via `range6` (e.g. `fd00:198:18::/96`): the v6 range mirrors
  the v4 ring slot for slot (`range6` base + slot offset), so a name's `A` and
  `AAAA` answers always point at the same slot, and eviction / persistence are
  unchanged. The prefix needs at least as many host bits as `range` (a `/15`
  range → at most `/111`). Without `range6`, `AAAA` for a faked name returns an
  empty NOERROR (IPv4 only). `HTTPS`/`SVCB` always do, since their hints would
  carry real addresses and ECH keys that bypass the mapping.
- `exclude` (suffixes, on top of the built-in `local`, `lan`, `localdomain`,
  `localhost`, `home.arpa` and reverse zones) always get real answers — put
  NTP / STUN / anything that needs a real address there. A non-empty `include`
  turns it into a whitelist.
- The pool is a ring: idle slots (10 min) are recycled, and only a pool full
  of busy entries evicts its oldest mapping. With `dns.store` the mappings
  survive restarts (see below); without it, a client still holding a fake
  address after a restart is dropped and succeeds once it re-resolves.
- A process that bypasses silk's DNS (DoH/DoT, hard-coded IPs, a local cache
  such as `systemd-resolved` caching an answer) gets or keeps whatever it got:
  real addresses take the normal path; fake ones are mapped as above.

## Logging

`general.log` sets the level: `off`, `error`, `warn`, `info` (default), `debug`
or `trace`. A set `RUST_LOG` environment variable overrides it.

## Per-process policy (cgroup v2)

`cgroups:` groups cgroup v2 paths by mode — `bypass` (never captured) or a node
name (public destinations forced through that node; `block` still blocks):

```yaml
cgroups:
  bypass:
    - system.slice/frps.service
  hy2:
    - qbittorrent
    - machine.slice/docker-abc123.scope
```

A cgroup may appear under one mode only. A bare
name such as `qbittorrent` is shorthand for `system.slice/qbittorrent.service`;
any other path (`user-1000.slice/session-c1.scope`, ...) is written in full.
The eBPF side asks `bpf_skb_ancestor_cgroup_id()` for the socket's cgroup
ancestry, so a rule covers the whole subtree and the deepest match wins. Only
host-originated traffic is affected, and the lookup is skipped entirely when
no rule is configured. Needs cgroup v2 and a kernel with `CONFIG_CGROUPS`. Put
a program in a cgroup with a systemd unit or
`systemd-run --scope -p Slice=... <cmd>`.

## Nodes

`nodes:` is a list; `type` selects the protocol, `name` is unique and is what
`general.default`, `rules` and `cgroups` refer to. The same type may appear
any number of times, and protocols you do not use are simply not written.

- `socks` (alias `socks5`) — `server`, optional `username`/`password`.
- `hysteria2` — `server` (`host:port`), `password`, `sni`, `insecure`, and
  optional `up`/`down` bandwidth. Implemented over QUIC (quinn) with raw
  HTTP/3 auth, sing-box-matching windows, BBR congestion control
  (Brutal-like initial window when `up` is set); TCP via QUIC streams, UDP
  via QUIC datagrams with fragmentation/reassembly.
- `vless` — `server`, `uuid`, `network` (`tcp`|`ws`), `tls`, `sni`,
  `insecure`, `ws_path`, `ws_host`.

Server hostnames are resolved before the eBPF hooks attach (through
`dns.default` when set), so lookups never loop through the datapath. `dns.remote` (the overseas resolver) is queried
through the node a domain routes to (the default node for unmatched names).

## Shutdown & cleanup

SIGINT/SIGTERM trigger an orderly teardown: the netlink-attached TC
filters (`tc qdisc del ... clsact`), the `silk0` veth bridge and the
`silkns` namespace are all removed — they outlive the process
otherwise. The same cleanup runs if a relay loop dies.

## Rulesets

Rules are `"kind,value,verdict"` lines under `rules:`, first match wins.

- `source`: plain list **or** sing-box JSON. Parsed into ordinary
  domain/cidr rules — **no FST at startup** (fine for small sets).
- `binary`: ARST FST ruleset for large domain lists, a plain file with **no
  suffix**, recognised by its ARST magic. Convert with:
  ```sh
  silk --convert-ruleset geosite-cn.json /etc/silk/cn-domain
  # also accepts plain .list text; a trailing ".ars" on the output is dropped
  ```
  Then reference it as `binary,/etc/silk/cn-domain,<verdict>`.

## Requirements

- Linux ≥ 6.6 (TCX/SchedClassifier attach; developed against honk's 6.12+ target)
- root privileges (TC, sk_lookup, netns, IP_TRANSPARENT)
- `iproute2` (`ip`, `tc`), and at least one node server (SOCKS5 with CONNECT +
  UDP ASSOCIATE, a Hysteria2 server, or a VLESS server) if anything routes to a node

## Build

Default release binary is **fully static musl** (`*-unknown-linux-musl`).
A glibc (gnu) build remains possible if you omit the musl target.

```sh
# 0. Toolchain
rustup toolchain install stable
rustup target add aarch64-unknown-linux-musl   # or x86_64-unknown-linux-musl
# Debian/Ubuntu: sudo apt-get install -y musl-tools
# (provides musl-gcc / aarch64-linux-musl-gcc on native hosts)

# 1. eBPF object (nightly, bpf-linker)
rustup component add rust-src --toolchain nightly
# Prefer the prebuilt bpf-linker matching your arch, e.g.:
#   https://github.com/aya-rs/bpf-linker/releases
# Or build from source — bpf-linker must match rustc nightly's LLVM
# (rustc +nightly -vV | grep llvm-version). Example for LLVM-22 on Ubuntu 24.04:
#   apt-get install -y llvm-22-dev libpolly-22-dev
#   LLVM_CONFIG_PATH=/usr/lib/llvm-22/bin/llvm-config \
#   RUSTFLAGS="-L /usr/lib/llvm-22/lib -C link-arg=-Wl,-rpath,/usr/lib/llvm-22/lib" \
#     cargo install bpf-linker --version 0.11.1 --no-default-features --features llvm-22

cd silk-ebpf
cargo +nightly build --release -Zbuild-std=core --target bpfel-unknown-none

# 2. Userspace — musl static (recommended)
cd ..
export RUSTFLAGS="-C target-feature=+crt-static -C link-self-contained=yes"
cargo +stable build --release --features ebpf \
  --target aarch64-unknown-linux-musl
# binary: target/aarch64-unknown-linux-musl/release/silk
# check: file ... && ldd ...   # expect "statically linked" / "not a dynamic executable"

# Optional: glibc (gnu) dynamic build
# cargo +stable build --release --features ebpf
# binary: target/release/silk
```

Note: bpf-linker's LLVM must match the rustc nightly's bundled LLVM —
older linkers (0.9.x) can't read LLVM 22 bitcode; 0.11.x needs a matching
system LLVM for the chosen feature.

## Run

```sh
# musl static build
sudo ./target/aarch64-unknown-linux-musl/release/silk -c /etc/silk/config.yaml
# or if you built the gnu default:
# sudo ./target/release/silk -c /etc/silk/config.yaml
```

Configuration is YAML (`serde_yaml_ng`); see `config.example.yaml`. The
default path is `/etc/silk/config.yaml`.

## What's intentionally missing (vs honk)

- No geoip/geosite databases, no logic/parameter expressions
- TCP/UDP via SOCKS5, Hysteria2 or VLESS only (no Salamander/Gecko obfuscation)
- Only plain UDP/53 DNS hijack of *clients'* queries (no DoH/DoT interception); upstreams may be udp/tcp/tls/https
- No node groups / failover / load balancing; one domestic + one overseas DNS upstream
- No fragment reassembly routing (fragments fall through to
  address/port-less surfaces like dae)

## License

GPL-3.0-only. The eBPF side follows honk's design and this project
inherits that choice; see honk's licensing notes.
