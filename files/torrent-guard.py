#!/usr/bin/env python3
# Managed by Ansible (ansible-role-torrent-guard)
"""Which WireGuard / AmneziaWG peers run BitTorrent?

Two signals per peer (tunnel address -> pubkey via `awg show allowed-ips`):

    signatures  iptables string match on the first packets of every flow coming
                from the tunnel (mangle FORWARD, before SNAT). A hit adds the source
                address to an ipset `tg_<kind>`; ipset counters count the packets.
    behaviour   one `conntrack -L` per run: flows, distinct destinations and UDP
                flows to high ports per tunnel address (max per buffer window).

Mode `monitor` only records; `block` also drops the matched flow (CONNMARK).

    collect   ensure rules, read ipsets + conntrack, merge into the buffer (timer)
    push      POST the buffer, clear it only on HTTP 2xx (timer)
    rules     (re)apply the iptables chain and ipsets
    status    print the buffer summary
    show      print the current per-peer view, buffer untouched

`--dry-run`: collect / push / rules only print what they would do.
"""

import fcntl
import hashlib
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

IFACE = os.environ.get("TG_IFACE", "awg0")
CLI = os.environ.get("TG_CLI", "awg")
SERVER = os.environ.get("TG_SERVER", "")
MODE = os.environ.get("TG_MODE", "monitor")
URL = os.environ.get("TG_URL", "")
TOKEN = os.environ.get("TG_TOKEN", "")
TIMEOUT = int(os.environ.get("TG_TIMEOUT", "30"))
STATE_DIR = os.environ.get("TG_STATE_DIR", "/var/lib/torrent-guard")
MAX_ENTRIES = int(os.environ.get("TG_MAX_ENTRIES", "5000"))
SET_TIMEOUT = int(os.environ.get("TG_SET_TIMEOUT", "86400"))
FIRST_PACKETS = int(os.environ.get("TG_FIRST_PACKETS", "4"))
LOG_FILE = os.environ.get("TG_LOG_FILE", "")

BUFFER = os.path.join(STATE_DIR, "buffer.json")
COUNTERS = os.path.join(STATE_DIR, "counters.json")
LOCK = os.path.join(STATE_DIR, "lock")

CHAIN = "TORRENT_GUARD"
MARK = "0x7470"
SKIP_PORTS = "53,443"

## Destination ports where reaching many hosts is normal: web, DNS, NTP/Roughtime, mail,
## DoT, RTSP/RTMP, STUN/TURN/RTP (calls), XMPP/push, Windows Update delivery (7680).
## Not counted in the fan-out; list after forestsnet/torrent-blocker measurements.
COMMON_PORTS = frozenset(
    {22, 53, 80, 123, 443, 465, 554, 587, 853, 993, 995, 1935, 2002, 5222, 5223, 5228,
     5349, 7680, 8080, 8443}
    | set(range(3478, 3498)) | set(range(16384, 16404)) | set(range(19302, 19310))
)

## xt_string offsets count from the start of the IP header
UDP_PAYLOAD = 20 + 8
## xt_u32: start of the UDP header whatever the IP header length (payload = +8)
U32_L4 = "0>>22&0x3C@"

## kind -> iptables match arguments
SIGNATURES = [
    # BEP 15 connect: magic 0x41727101980 + action 0
    ("trk", ["-p", "udp", "-m", "u32", "--u32",
             f"{U32_L4}8=0x417 && {U32_L4}12=0x27101980 && {U32_L4}16=0"]),
    ("dht", ["-p", "udp", "-m", "string", "--algo", "bm", "--string", "d1:ad2:id20:",
             "--from", str(UDP_PAYLOAD), "--to", str(UDP_PAYLOAD + 36)]),
    # BEP 42: a reply may start with the "ip" key, so "1:r..." is not at offset 0
    ("dht", ["-p", "udp", "-m", "string", "--algo", "bm", "--string", "1:rd2:id20:",
             "--from", str(UDP_PAYLOAD), "--to", str(UDP_PAYLOAD + 68)]),
    # Keys nDPI looks for anywhere: clients that do not sort the bencode dict
    ("dht", ["-p", "udp", "-m", "string", "--algo", "bm", "--string", ":info_hash20:"]),
    ("dht", ["-p", "udp", "-m", "string", "--algo", "bm", "--string", ":target20:"]),
    # BEP 29 ST_SYN: version 1/type SYN, no extension, conn_id != 0, tdiff 0, seq 1.
    # The uTP header stays plain under MSE, so this sees encrypted peers too. A bare
    # 0x4100 also matches TURN/WebRTC media; the full header check does not.
    ("utp", ["-p", "udp", "-m", "u32", "--u32",
             f"{U32_L4}8>>16=0x4100 && {U32_L4}8&0xFFFF=1:0xFFFF"
             f" && {U32_L4}16=0 && {U32_L4}24>>16=1"]),
    ("bt", ["-m", "string", "--algo", "bm", "--string", "BitTorrent protocol", "--to", "160"]),
    ("http", ["-p", "tcp", "-m", "string", "--algo", "bm", "--string", "info_hash=", "--to", "1024"]),
    ("ext", ["-m", "string", "--algo", "bm", "--string", "ut_metadata"]),
    ("ext", ["-m", "string", "--algo", "bm", "--string", "ut_pex"]),
]
KINDS = sorted({kind for kind, _ in SIGNATURES})

KV_RE = re.compile(r"(src|dst|sport|dport)=(\S+)")


def log(msg):
    print(msg, flush=True)
    if not LOG_FILE:
        return
    try:
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        with open(LOG_FILE, "a") as fh:
            fh.write(f"{stamp} {msg}\n")
    except OSError as exc:
        print(f"log file {LOG_FILE}: {exc}", file=sys.stderr, flush=True)


def run(cmd, check=True):
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if check and res.returncode != 0:
        raise RuntimeError(f"{' '.join(cmd)}: rc={res.returncode} {res.stderr.strip()}")
    return res


# ==================== iptables / ipset ====================

def set_name(kind):
    return f"tg_{kind}"


def sub_chain(kind):
    return f"TG_{kind.upper()}"


def rule_plan(mode):
    """-> (version, {chain: [rule args]}). The version tag lets `ensure_rules`
    skip the rebuild when the live chain already matches."""
    main = [["-m", "connbytes", "--connbytes", f"{FIRST_PACKETS + 1}:",
             "--connbytes-dir", "original", "--connbytes-mode", "packets", "-j", "RETURN"],
            ["-p", "tcp", "-m", "multiport", "--dports", SKIP_PORTS, "-j", "RETURN"],
            ["-p", "udp", "-m", "multiport", "--dports", SKIP_PORTS, "-j", "RETURN"]]
    if mode == "block":
        main.insert(0, ["-m", "connmark", "--mark", MARK, "-j", "DROP"])
    main += [match + ["-j", sub_chain(kind)] for kind, match in SIGNATURES]
    chains = {CHAIN: main}
    for kind in KINDS:
        # Add only when absent: re-adding with --exist resets the entry's counters
        rules = [["-m", "set", "!", "--match-set", set_name(kind), "src", "!", "--update-counters",
                  "-j", "SET", "--add-set", set_name(kind), "src"]]
        if mode == "block":
            rules.append(["-j", "CONNMARK", "--set-mark", MARK])
        verdict = "DROP" if mode == "block" else "RETURN"
        rules.append(["-m", "set", "--match-set", set_name(kind), "src", "-j", verdict])
        chains[sub_chain(kind)] = rules
    spec = json.dumps({"iface": IFACE, "timeout": SET_TIMEOUT, "chains": chains}, sort_keys=True)
    version = hashlib.sha256(spec.encode()).hexdigest()[:12]
    chains[CHAIN].insert(0, ["-m", "comment", "--comment", rule_tag(mode, version)])
    return version, chains


def rule_tag(mode, version):
    return f"torrent-guard {mode} {version}"


def rule_commands(mode):
    """Full rebuild: ipsets, chains (flushed and refilled), jump from FORWARD."""
    _, chains = rule_plan(mode)
    cmds = [["ipset", "create", set_name(kind), "hash:ip", "timeout", str(SET_TIMEOUT),
             "counters", "-exist"] for kind in KINDS]
    for chain in chains:
        cmds.append(["iptables", "-t", "mangle", "-N", chain])
        cmds.append(["iptables", "-t", "mangle", "-F", chain])
    for chain, rules in chains.items():
        cmds += [["iptables", "-t", "mangle", "-A", chain] + rule for rule in rules]
    return cmds


def jump_rule():
    return ["FORWARD", "-i", IFACE, "-j", CHAIN]


def jump_present():
    return run(["iptables", "-t", "mangle", "-C"] + jump_rule(), check=False).returncode == 0


def rules_current(mode):
    version, _ = rule_plan(mode)
    live = run(["iptables", "-t", "mangle", "-S", CHAIN], check=False)
    return live.returncode == 0 and rule_tag(mode, version) in live.stdout and jump_present()


def ensure_rules(dry_run=False):
    if rules_current(MODE):
        return False
    cmds = rule_commands(MODE)
    if dry_run:
        for cmd in cmds:
            log("would run: " + " ".join(cmd))
        log("would run: iptables -t mangle -A " + " ".join(jump_rule()))
        return True
    for cmd in cmds:
        # -N on an existing chain fails; everything else must succeed
        run(cmd, check=cmd[3:4] != ["-N"])
    if not jump_present():
        run(["iptables", "-t", "mangle", "-A"] + jump_rule())
    log(f"rules: applied mode={MODE} iface={IFACE}")
    return True


def conntrack_acct_enabled():
    try:
        with open("/proc/sys/net/netfilter/nf_conntrack_acct") as fh:
            return fh.read().strip() == "1"
    except OSError:
        return False


# ==================== parsing ====================

def norm_ip(ip):
    return ipaddress.ip_address(ip.strip("[]")).compressed


def parse_allowed_ips(text):
    """`awg show <iface> allowed-ips` -> {tunnel_ip: pubkey} (single-host routes only)."""
    peers = {}
    for line in text.splitlines():
        parts = line.split("\t")
        if len(parts) != 2:
            continue
        for net in parts[1].split():
            try:
                net = ipaddress.ip_network(net, strict=False)
            except ValueError:
                continue
            if net.num_addresses == 1:
                peers[net.network_address.compressed] = parts[0]
    return peers


def parse_ipset(text):
    """`ipset list <set>` -> {ip: packets}."""
    out = {}
    members = False
    for line in text.splitlines():
        if line.startswith("Members:"):
            members = True
            continue
        if not members or not line.strip():
            continue
        fields = line.split()
        try:
            ip = norm_ip(fields[0])
            packets = int(fields[fields.index("packets") + 1]) if "packets" in fields else 0
        except (ValueError, IndexError):
            continue
        out[ip] = packets
    return out


## Per-peer conntrack metrics; the buffer keeps max_<name> of each
METRICS = ("flows", "dsts", "udp_hi", "fan_hosts", "fan_ports")


def parse_conntrack(text, known):
    """conntrack -L -f ipv4 lines -> {src: {metric: value}} for src in `known`.
    IPv4 output is already canonical, so addresses are compared as printed.

    fan_hosts / fan_ports: distinct destinations and ports outside COMMON_PORTS.
    A torrent client spreads over many hosts AND many ports; a game launcher or a
    call reaches many hosts on a few ports."""
    stats = {}
    for line in text.splitlines():
        start = line.find(" src=")
        if start < 0:
            continue
        src = line[start + 5:line.find(" ", start + 5)]
        if src not in known:  # most flows: the host itself or other peers' replies
            continue
        orig = {}
        for m in KV_RE.finditer(line, start):
            if m.group(1) in orig:  # second src= starts the reply tuple
                break
            orig[m.group(1)] = m.group(2)
        dst = orig.get("dst")
        if not dst:
            continue
        cur = stats.setdefault(src, {"flows": 0, "dsts": set(), "udp_hi": 0,
                                     "fan_hosts": set(), "fan_ports": set()})
        cur["flows"] += 1
        cur["dsts"].add(dst)
        dport = orig.get("dport", "")
        if not dport.isdigit():
            continue
        port = int(dport)
        if port in COMMON_PORTS:
            continue
        cur["fan_hosts"].add(dst)
        cur["fan_ports"].add(port)
        if port >= 1024 and line.split(None, 1)[0] == "udp":
            cur["udp_hi"] += 1
    return {ip: {m: len(v) if isinstance(v, set) else v for m, v in s.items()}
            for ip, s in stats.items()}


def counter_deltas(current, previous):
    """ipset packet counters -> new packets since the previous run. An entry that
    expired and came back restarts from zero, so a smaller value is all new."""
    deltas = {}
    for key, packets in current.items():
        prev = previous.get(key, 0)
        delta = packets - prev if packets >= prev else packets
        if delta > 0:
            deltas[key] = delta
    return deltas


# ==================== state ====================

def load_json(path, default):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (FileNotFoundError, ValueError):
        return default


def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w") as fh:
        json.dump(data, fh)
    os.replace(tmp, path)


def load_buffer():
    return load_json(BUFFER, {}).get("entries", {})


def save_buffer(entries):
    save_json(BUFFER, {"version": 1, "entries": entries})


def read_counters():
    """-> {"kind|ip": packets} over all ipsets."""
    out = {}
    for kind in KINDS:
        res = run(["ipset", "list", set_name(kind)], check=False)
        if res.returncode != 0:
            continue
        for ip, packets in parse_ipset(res.stdout).items():
            out[f"{kind}|{ip}"] = packets
    return out


def snapshot():
    """-> (peers {ip: pubkey}, conntrack stats {ip: ...}, counters {"kind|ip": packets})."""
    peers = parse_allowed_ips(run([CLI, "show", IFACE, "allowed-ips"]).stdout)
    flows = run(["conntrack", "-L", "-f", "ipv4"]).stdout
    return peers, parse_conntrack(flows, peers), read_counters()


def merge(entries, peers, stats, deltas, now):
    """Fold one run into the buffer; returns the number of hits without a peer."""
    orphan = 0
    per_ip = {}
    for key, delta in deltas.items():
        kind, ip = key.split("|", 1)
        if ip not in peers:
            orphan += delta
            continue
        per_ip.setdefault(ip, {})[kind] = delta
    for ip in set(stats) | set(per_ip):
        pubkey = peers.get(ip)
        if not pubkey:
            continue
        cur = entries.get(pubkey)
        if cur is None:
            if len(entries) >= MAX_ENTRIES:
                continue
            cur = entries[pubkey] = {"first_seen": now, "samples": 0, "hits": {}}
        cur["last_seen"] = now
        cur["samples"] += 1
        for kind, delta in per_ip.get(ip, {}).items():
            cur["hits"][kind] = cur["hits"].get(kind, 0) + delta
        s = stats.get(ip, {})
        for m in METRICS:
            cur[f"max_{m}"] = max(cur.get(f"max_{m}", 0), s.get(m, 0))
    return orphan


# ==================== actions ====================

def collect(dry_run=False):
    if not conntrack_acct_enabled():
        log("collect: warning: net.netfilter.nf_conntrack_acct=0, connbytes never matches")
    rebuilt = ensure_rules(dry_run)
    peers, stats, counters = snapshot()
    deltas = counter_deltas(counters, load_json(COUNTERS, {}))
    entries = load_buffer()
    orphan = merge(entries, peers, stats, deltas, int(time.time()))
    hits = {}
    for key, delta in deltas.items():
        kind = key.split("|", 1)[0]
        hits[kind] = hits.get(kind, 0) + delta
    with_hits = sum(1 for e in entries.values() if e["hits"])
    prefix = "collect (dry-run)" if dry_run else "collect"
    log(f"{prefix}: mode={MODE} rules_rebuilt={rebuilt} peers={len(peers)} active={len(stats)} "
        f"hits={hits} orphan_hits={orphan} buffer={len(entries)} with_hits={with_hits}")
    if dry_run:
        return
    save_json(COUNTERS, counters)
    save_buffer(entries)


def push(dry_run=False):
    entries = load_buffer()
    body = {
        "server": SERVER,
        "mode": MODE,
        "sent_at": int(time.time()),
        "entries": [{"pubkey": key, **val} for key, val in entries.items()],
    }
    if dry_run:
        top = sorted(body["entries"], key=lambda e: -sum(e["hits"].values()))[:10]
        log(f"push (dry-run): would POST {len(entries)} entries to {URL or '(no URL)'}")
        for e in top:
            log(f"  {e['pubkey']} hits={e['hits']} max_flows={e.get('max_flows', 0)} "
                f"fan={e.get('max_fan_hosts', 0)}/{e.get('max_fan_ports', 0)}")
        return
    if not URL or not TOKEN:
        log("push: URL or token not set, skipped")
        return
    req = urllib.request.Request(
        URL,
        data=json.dumps(body).encode(),
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {TOKEN}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            status = resp.status
    except urllib.error.HTTPError as exc:
        log(f"push: HTTP {exc.code}, buffer kept ({len(entries)} entries)")
        sys.exit(1)
    except (urllib.error.URLError, OSError) as exc:
        log(f"push: {exc}, buffer kept ({len(entries)} entries)")
        sys.exit(1)
    save_buffer({})
    log(f"push: HTTP {status}, sent {len(entries)} entries")


def rules(dry_run=False):
    if not ensure_rules(dry_run):
        log(f"rules: up to date (mode={MODE})")


def status(dry_run=False):
    entries = load_buffer()
    hits = {}
    for e in entries.values():
        for kind, n in e["hits"].items():
            hits[kind] = hits.get(kind, 0) + n
    log(json.dumps({"mode": MODE, "rules_current": rules_current(MODE), "entries": len(entries),
                    "with_hits": sum(1 for e in entries.values() if e["hits"]), "hits": hits}))


def show(dry_run=False):
    """Buffer since the last push: peers with hits first, then by fan-out."""
    entries = load_buffer()
    log(f"{'pubkey':44}  {'hits':32}  flows  dsts  fan_hosts/ports  samples")
    rows = sorted(entries.items(),
                  key=lambda kv: (-sum(kv[1]["hits"].values()), -kv[1].get("max_fan_ports", 0)))
    for pubkey, e in rows:
        hits = ",".join(f"{k}={v}" for k, v in sorted(e["hits"].items())) or "-"
        fan = f"{e.get('max_fan_hosts', 0)}/{e.get('max_fan_ports', 0)}"
        log(f"{pubkey:44}  {hits:32}  {e.get('max_flows', 0):5}  {e.get('max_dsts', 0):4}  "
            f"{fan:>15}  {e['samples']:7}")


def main():
    args = sys.argv[1:]
    dry_run = "--dry-run" in args
    args = [a for a in args if a != "--dry-run"]
    actions = {"collect": collect, "push": push, "rules": rules, "status": status, "show": show}
    cmd = args[0] if args else ""
    if cmd not in actions or MODE not in ("monitor", "block"):
        sys.exit(f"usage: {sys.argv[0]} {{{'|'.join(actions)}}} [--dry-run]  (TG_MODE=monitor|block)")
    os.makedirs(STATE_DIR, mode=0o700, exist_ok=True)
    with open(LOCK, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            actions[cmd](dry_run)
        except Exception as exc:
            log(f"{cmd}: error: {exc}")
            sys.exit(1)


if __name__ == "__main__":
    main()
