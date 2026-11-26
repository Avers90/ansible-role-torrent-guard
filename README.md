# ansible-role-torrent-guard

Find out which WireGuard / AmneziaWG peers run BitTorrent. Monitor mode (default)
only records; block mode also drops the matched flows.

## How it detects

Two independent signals, both keyed by the peer's tunnel address and mapped to its
public key via `awg show <iface> allowed-ips`:

**Signatures** — iptables `string` match in `mangle FORWARD -i <iface>` (traffic from
peers, before SNAT), only on the first `torrent_guard_first_packets` packets of each
flow (`connbytes`), skipping TCP/UDP 53 and 443:

| ipset | What | Match |
|---|---|---|
| `tg_trk` | UDP tracker connect (BEP 15) | `u32`: magic `0x41727101980` + action 0 |
| `tg_dht` | DHT query / reply (KRPC) | `d1:ad2:id20:` / `1:rd2:id20:`, `:info_hash20:` / `:target20:` anywhere |
| `tg_utp` | uTP connection start (BEP 29 `ST_SYN`) | `u32`: bare 20-byte header `0x41 0x00`, conn_id ≠ 0, timestamp ≠ 0, tdiff 0 (seq not checked: libtorrent randomizes it) |
| `tg_bt` | peer handshake (TCP, uTP) | `\x13BitTorrent protocol` |
| `tg_http` | HTTP tracker announce | `info_hash=` |
| `tg_ext` | extension handshake (magnet, PEX) | `ut_metadata` / `ut_pex` |

A hit adds the source to the ipset (`hash:ip timeout counters`) once; the ipset
packet counter counts later hits (re-adding with `--exist` would reset it, so the
entry expires `torrent_guard_set_timeout` after the first hit and starts again). DHT and trackers are what public "who downloads what" crawlers
see, and a client cannot find peers without them. Encrypted peer traffic (MSE) has
no signature, but over uTP its header stays plain, so `tg_utp` still sees the
connection start. A bare `0x4100` would also match TURN/WebRTC media; the full
header check does not (rules cross-checked with forestsnet/torrent-blocker and nDPI).

**Behaviour** — one `conntrack -L` per run, per tunnel address: flows, distinct
destination IPs, and the fan-out — distinct destination hosts and ports outside
common service ports (web, DNS, mail, STUN/TURN/RTP, NTP, push, Windows Update
delivery). The buffer keeps the maximum seen since the last push. A torrent client
spreads over many hosts **and** many ports; a call or a game launcher reaches many
hosts on a few ports, a browser stays on 443. `udp_hi` (UDP flows to high ports) skips the same
common ports.

In `block` mode a hit also sets a connmark and drops the packet; later packets of
the marked flow are dropped too. The peer's other traffic is not affected.

## How it runs

| Unit | When | What |
|---|---|---|
| `torrent-guard-collect.timer` | every 5 min | re-apply rules if missing, read ipsets + conntrack, merge into `/var/lib/torrent-guard/buffer.json` |
| `torrent-guard-push.timer` | hourly + up to 10 min jitter | POST the buffer, clear it only on HTTP 2xx |
| `torrent-guard@rules.service` | on role changes | (re)build the chain and ipsets |

The chain carries a version tag (mode, interface, signatures). `collect` rebuilds it
only when the tag is missing — e.g. after a firewall run flushed the mangle table —
so the rules come back within one collect interval.

Units run `Nice=19`, `IOSchedulingClass=idle`, `CPUQuota=10%`, `MemoryMax=128M`, with
`ProtectSystem=strict` and only `CAP_NET_ADMIN` + `CAP_NET_RAW`. The role sets
`net.netfilter.nf_conntrack_acct=1` in its own sysctl file: without it `connbytes`
silently never matches.

Every run writes one line to journald and `/var/log/torrent-guard/torrent-guard.log`:

```
2026-11-26T12:05:09Z collect: mode=monitor rules_rebuilt=False peers=180 active=64 hits={'dht': 412, 'trk': 3} orphan_hits=0 buffer=71 with_hits=2
2026-11-26T13:04:41Z push: HTTP 200, sent 71 entries
```

## Requirements

- Debian / Ubuntu, `python3` (stdlib only), `ansible.posix` collection
- AmneziaWG (`awg`) or WireGuard (`wg`) interface, one /32 per peer

## Role Variables

| Variable | Default | Description |
|---|---|---|
| `torrent_guard_interface` | `amneziawg_interface` / `wireguard_interface` | Tunnel interface |
| `torrent_guard_wg_cli` | `awg` if `amneziawg_interface` is set, else `wg` | CLI for `show allowed-ips` |
| `torrent_guard_mode` | `monitor` | `monitor` or `block` |
| `torrent_guard_server_code` | `inventory_hostname_short` | Server id sent in each batch |
| `torrent_guard_first_packets` | `4` | Packets per flow to scan |
| `torrent_guard_set_timeout` | `86400` | Seconds a source stays in a hit ipset |
| `torrent_guard_collect_interval` | `5min` | Collect interval (systemd time span) |
| `torrent_guard_push_url` | `""` | HTTPS endpoint; empty = collect only |
| `torrent_guard_push_token` | `""` | Bearer token (vault), required with URL |
| `torrent_guard_push_on_calendar` | `hourly` | Push schedule (`OnCalendar`) |
| `torrent_guard_push_randomized_delay` | `10min` | Push jitter |
| `torrent_guard_push_timeout` | `30` | HTTP timeout, seconds |
| `torrent_guard_max_entries` | `5000` | Buffer cap (peers) |
| `torrent_guard_cpu_quota` / `_memory_max` | `10%` / `128M` | systemd limits |
| `torrent_guard_log_dir` | `/var/log/torrent-guard` | Own log file, empty = journald only |
| `torrent_guard_log_rotate_weeks` | `8` | logrotate: weekly, N kept |

## Push format

`POST <url>`, `Authorization: Bearer <token>`, `Content-Type: application/json`:

```json
{
  "server": "awg-de-01",
  "mode": "monitor",
  "sent_at": 1795690800,
  "entries": [
    {"pubkey": "Ab3k...=", "first_seen": 1795687500, "last_seen": 1795690500, "samples": 11,
     "hits": {"dht": 412, "trk": 3}, "max_flows": 950, "max_dsts": 610, "max_udp_hi": 870,
     "max_fan_hosts": 480, "max_fan_ports": 455}
  ]
}
```

Times are unix seconds (UTC). One entry per peer active since the last successful
push (`hits` is empty for clean peers — their `max_*` values help pick thresholds).
An empty `entries` list is still sent as a heartbeat. Any 2xx clears the buffer.

## Example Playbook

```yaml
- hosts: awg_servers
  become: true
  roles:
    - role: torrent-guard
      vars:
        torrent_guard_push_url: "https://example.com/internal/torrent-hits"
        torrent_guard_push_token: "{{ vault_torrent_guard_token }}"
```

Run it after the firewall role. The firewall flushes the mangle table; the next
collect run puts the chain back.

## Manual checks

```bash
sudo sh -c 'set -a; . /etc/torrent-guard.env; torrent-guard show'            # buffer since the last push
sudo sh -c 'set -a; . /etc/torrent-guard.env; torrent-guard status'
sudo sh -c 'set -a; . /etc/torrent-guard.env; torrent-guard collect --dry-run'
sudo sh -c 'set -a; . /etc/torrent-guard.env; torrent-guard push --dry-run'
sudo iptables -t mangle -S TORRENT_GUARD
sudo ipset list tg_dht
sudo tail -n 20 /var/log/torrent-guard/torrent-guard.log
```

`--dry-run` never writes the buffer, never changes iptables and never sends.

## License

MIT
