#!/usr/bin/env python3
"""tephra-sensor: records what a CI job does on its runner and, in block mode, stops egress it didn't declare.

  DNS          a local DNS proxy logs every lookup (and refuses non-allowed names in block mode, which also
               stops DNS tunnelling)
  connections  an iptables LOG rule records every new outbound connection; each is matched to the process
               that opened it and to the domain it resolved
  processes    Linux process events (netlink proc connector) record every program executed
  files        tracked source files changed during the job are listed at the end
  block mode   iptables rejects new connections to anything not resolved from an allowed domain
  threat intel known-bad domains and IPs (from Tephra Trace, else public feeds) are refused in either mode
  actions      the GitHub Actions the runner downloaded for the job (nested ones included) are listed

Standard library only. Needs root (passwordless sudo on GitHub-hosted Linux runners).

  sensor.py start   set up, then keep running in the background
  sensor.py stop    tear down, write summary.json and the step summary
  sensor.py run     foreground (tests)

Configuration (environment): TEPHRA_MODE=audit|block, TEPHRA_ALLOWED (domains / IPs / CIDRs, newline or
comma separated), TEPHRA_DIR (output folder), TEPHRA_CONSOLE_URL + TEPHRA_INGEST_TOKEN (optional live
streaming), TEPHRA_DNS_LISTEN (default 127.0.0.1:53), TEPHRA_DNS_UPSTREAM (default: current resolver),
TEPHRA_WORKSPACE (default GITHUB_WORKSPACE), TEPHRA_REWRITE_RESOLV (default true), TEPHRA_INTEL (on|off,
default on).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import base64
import glob
import json
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request

VERSION = "1.3.0"
MAX_PACKAGES = 5000
OIDC_AUDIENCE = "tephra-trace"     # the audience Tephra Trace accepts on sensor OIDC tokens
LOG_NEW, LOG_BLOCK, LOG_FWD, LOG_INTEL = "tephra-new ", "tephra-block ", "tephra-fwd ", "tephra-intel "
CHAINS = ("TEPHRA_LOG", "TEPHRA_OUT", "TEPHRA_INTEL", "TEPHRA_INTEL_HIT")   # teardown order matters: INTEL before HIT
# public feeds the sensor reads itself when it has no console to ask (no keys needed)
PUBLIC_FEEDS = {"feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
                "spamhaus_drop": "https://www.spamhaus.org/drop/drop_v4.json"}
MAX_INTEL_NETS = 8000
# what the GitHub runner itself needs; always allowed in block mode
RUNNER_ENDPOINTS = ["github.com", "api.github.com", "*.github.com", "*.githubusercontent.com",
                    "*.actions.githubusercontent.com", "*.blob.core.windows.net", "ghcr.io", "*.ghcr.io",
                    "*.githubapp.com"]
PLATFORM_IPS = ["169.254.169.254", "168.63.129.16"]   # instance metadata, Azure platform/DNS
MAX_RAW = 20000
SECRET_PATTERNS = [
    (re.compile(r"(gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})"), "<github-token>"),
    (re.compile(r"\b(A[SK]IA[A-Z0-9]{16})\b"), "<aws-key-id>"),
    (re.compile(r"(?i)(authorization:\s*(bearer|basic|token)\s+)\S+"), r"\1<redacted>"),
    (re.compile(r"(?i)((?:--?)(?:password|passwd|token|secret|api-key|apikey|client-secret)[= ])\S+"), r"\1<redacted>"),
    (re.compile(r"(?i)\b((?:password|passwd|token|secret|apikey|api_key|client_secret)=)[^\s&]+"), r"\1<redacted>"),
    (re.compile(r"(https?://)[^/\s:@]+:[^/\s@]+@"), r"\1<redacted>@"),
]


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


# each destination is one record (first time + count); it also keeps up to MAX_TIMES later connection times,
# at least TIME_SPACING_S apart, so a later call to the same host (e.g. the credential broker after a secret
# read) still has its own timestamp
MAX_TIMES, TIME_SPACING_S = 20, 5.0


def _secs(a: str, b: str) -> float:
    p = lambda s: dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    return (p(b) - p(a)).total_seconds()


def redact(s: str) -> str:
    for rx, rep in SECRET_PATTERNS:
        s = rx.sub(rep, s)
    return s


def split_list(v: str) -> list[str]:
    return [x.strip().lower().rstrip(".") for x in re.split(r"[\n,]", v or "") if x.strip()]


# ---------- allowlist ----------

class Allowlist:
    def __init__(self, entries: list[str]):
        self.domains, self.nets = [], []
        for e in entries:
            e = e.split(":")[0] if e.count(":") == 1 else e     # host:port -> host (ports aren't enforced)
            try:
                self.nets.append(ipaddress.ip_network(e, strict=False))
            except ValueError:
                self.domains.append(e)

    def domain(self, name: str) -> bool:
        name = name.lower().rstrip(".")
        for d in self.domains:
            if d.startswith("*."):
                if name == d[2:] or name.endswith(d[1:]):
                    return True
            elif name == d:
                return True
        return False

    def ip(self, ip: str) -> bool:
        try:
            a = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(a in n for n in self.nets if n.version == a.version)


class KnownBad:
    """Known-bad domains: a listed name covers its subdomains too."""
    def __init__(self, domains: list[str]):
        self.domains = {d.strip().lower().rstrip(".") for d in domains if d and d.strip()}

    def domain(self, name: str) -> bool:
        parts = name.lower().rstrip(".").split(".")
        return any(".".join(parts[i:]) in self.domains for i in range(len(parts) - 1))


# never refused, whatever a feed says: the runner's own endpoints and big shared platforms builds depend on
CORE = Allowlist(RUNNER_ENDPOINTS + ["*.amazonaws.com", "*.cloudfront.net", "*.windows.net", "*.azure.com",
                                     "*.googleapis.com", "*.docker.io", "*.docker.com", "*.npmjs.org", "*.pypi.org",
                                     "*.pythonhosted.org", "*.github.io", "*.beyondtrust.io", "*.tephrasecurity.com"])


# ---------- DNS wire format ----------

def read_name(buf: bytes, off: int) -> tuple[str, int]:
    labels, jumped, end, hops = [], False, off, 0
    while True:
        n = buf[off]
        if n == 0:
            off += 1
            break
        if n & 0xC0 == 0xC0:
            ptr = struct.unpack(">H", buf[off:off + 2])[0] & 0x3FFF
            if not jumped:
                end = off + 2
            off, jumped, hops = ptr, True, hops + 1
            if hops > 20:
                raise ValueError("DNS name loop")
            continue
        labels.append(buf[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(labels).lower(), (end if jumped else off)


def parse_query(q: bytes) -> tuple[str, int, int]:
    """name, qtype, end offset of the question"""
    name, off = read_name(q, 12)
    qtype = struct.unpack(">H", q[off:off + 2])[0]
    return name, qtype, off + 4


def nxdomain(q: bytes) -> bytes:
    _, _, qend = parse_query(q)
    qid, qflags = struct.unpack(">HH", q[:4])
    flags = 0x8000 | (qflags & 0x7900) | 0x0080 | 3      # response, keep opcode+RD, RA, NXDOMAIN
    return struct.pack(">HHHHHH", qid, flags, 1, 0, 0, 0) + q[12:qend]


def parse_answers(r: bytes) -> list[tuple[str, int, str]]:
    """[(name, type, value)] for A, AAAA and CNAME records"""
    an = struct.unpack(">H", r[6:8])[0]
    qd = struct.unpack(">H", r[4:6])[0]
    off = 12
    for _ in range(qd):
        _, off = read_name(r, off)
        off += 4
    out = []
    for _ in range(an):
        name, off = read_name(r, off)
        rtype, _, _, rdlen = struct.unpack(">HHIH", r[off:off + 10])
        off += 10
        rdata = r[off:off + rdlen]
        if rtype == 1 and rdlen == 4:
            out.append((name, 1, socket.inet_ntop(socket.AF_INET, rdata)))
        elif rtype == 28 and rdlen == 16:
            out.append((name, 28, socket.inet_ntop(socket.AF_INET6, rdata)))
        elif rtype == 5:
            out.append((name, 5, read_name(r, off)[0]))
        off += rdlen
    return out


def addr(v: str, default_port: int = 53) -> tuple[str, int]:
    if v.startswith("["):
        host, _, port = v[1:].partition("]:")
        return host, int(port or default_port)
    if v.count(":") == 1:
        h, p = v.split(":")
        return h, int(p)
    return v, default_port


# ---------- firewall ----------

def host_facts(env: dict) -> dict:
    """What the runner is: OS and version, GitHub's image, and apt's version and retry setting (CVE-2026-109518)."""
    facts: dict = {}
    try:
        with open("/etc/os-release") as f:
            kv = dict(line.rstrip().split("=", 1) for line in f if "=" in line)
        facts["os"], facts["os_version"] = kv.get("ID", "").strip('"'), kv.get("VERSION_ID", "").strip('"')
    except OSError:
        pass
    if env.get("ImageOS") or env.get("ImageVersion"):
        facts["image"] = f"{env.get('ImageOS', '')} {env.get('ImageVersion', '')}".strip()
    for key, cmd in (("apt", ["dpkg-query", "-W", "-f=${Version}", "apt"]),
                     ("apt_retries", ["apt-config", "shell", "R", "Acquire::Retries"])):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            continue
        if key == "apt_retries":
            out = out.partition("=")[2].strip("'\"") if out else "default"
        if out:
            facts[key] = out[:60]
    return facts


class Firewall:
    def __init__(self, sensor: "Sensor"):
        self.s = sensor
        self.families = [("iptables", 4)] + ([("ip6tables", 6)] if self._works("ip6tables") else [])
        self.allowed_ips: set[str] = set()
        self.lock = threading.Lock()

    @staticmethod
    def _works(cmd: str) -> bool:
        try:
            return subprocess.run([cmd, "-w", "-L", "OUTPUT", "-n"], capture_output=True, timeout=10).returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def _ipt(self, cmd: str, *args: str, check: bool = True) -> bool:
        r = subprocess.run([cmd, "-w", *args], capture_output=True, text=True, timeout=15)
        if r.returncode and check:
            self.s.error(f"{cmd} {' '.join(args)}: {r.stderr.strip()[:200]}")
        return r.returncode == 0

    # traffic that never leaves the local network segment: IPv6 router and neighbour discovery, multicast and
    # broadcast (DHCP). It isn't egress, so it's neither logged nor blocked; blocking it can break networking.
    LOCAL = {4: [["-d", "224.0.0.0/4"], ["-d", "255.255.255.255/32"]],
             6: [["-d", "ff00::/8"], ["-d", "fe80::/10"]]
             + [["-p", "ipv6-icmp", "--icmpv6-type", t] for t in ("133", "134", "135", "136")]}

    def setup(self, block: bool, fixed: list[str], dns_ips: list[str]) -> None:
        self.teardown(quiet=True)
        for cmd, fam in self.families:
            self._ipt(cmd, "-N", "TEPHRA_LOG")
            for rule in self.LOCAL[fam]:
                self._ipt(cmd, "-A", "TEPHRA_LOG", *rule, "-j", "RETURN")
            self._ipt(cmd, "-A", "TEPHRA_LOG", "!", "-o", "lo", "-m", "conntrack", "--ctstate", "NEW",
                      "-j", "LOG", "--log-prefix", LOG_NEW, "--log-uid")
            self._ipt(cmd, "-I", "OUTPUT", "1", "-j", "TEPHRA_LOG")
            if self._ipt(cmd, "-L", "DOCKER-USER", "-n", check=False):   # containers go through FORWARD
                self._ipt(cmd, "-I", "DOCKER-USER", "1", "-m", "conntrack", "--ctstate", "NEW", "-j", "LOG",
                          "--log-prefix", LOG_FWD)
            if not block:
                continue
            self._ipt(cmd, "-N", "TEPHRA_OUT")
            for rule in (["-o", "lo", "-j", "RETURN"], *[[*r, "-j", "RETURN"] for r in self.LOCAL[fam]],
                         ["-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN"],
                         ["-m", "owner", "--uid-owner", "systemd-resolve", "-p", "udp", "--dport", "53", "-j", "RETURN"],
                         ["-m", "owner", "--uid-owner", "systemd-resolve", "-p", "tcp", "--dport", "53", "-j", "RETURN"],
                         ["-j", "LOG", "--log-prefix", LOG_BLOCK, "--log-uid"],
                         ["-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"],
                         ["-j", "REJECT"]):
                self._ipt(cmd, "-A", "TEPHRA_OUT", *rule, check="systemd-resolve" not in rule)
            self._ipt(cmd, "-I", "OUTPUT", "2", "-j", "TEPHRA_OUT")
        for ip in fixed:
            self.allow(ip)
        for ip in dns_ips:
            self.allow(ip, port=53)

    def deny_known_bad(self, nets: list[str]) -> int:
        """Reject (and log) connections to known-bad addresses, in any mode. Loaded in one iptables-restore per
        family: thousands of rules one call at a time would delay the job."""
        added = 0
        for cmd, fam in self.families:
            mine = [n for n in nets if ipaddress.ip_network(n, strict=False).version == fam][:MAX_INTEL_NETS]
            if not mine:
                continue
            lines = ["*filter", ":TEPHRA_INTEL - [0:0]", ":TEPHRA_INTEL_HIT - [0:0]",
                     f'-A TEPHRA_INTEL_HIT -j LOG --log-prefix "{LOG_INTEL}" --log-uid',
                     "-A TEPHRA_INTEL_HIT -p tcp -j REJECT --reject-with tcp-reset", "-A TEPHRA_INTEL_HIT -j REJECT"]
            lines += [f"-A TEPHRA_INTEL -d {n} -j TEPHRA_INTEL_HIT" for n in mine] + ["COMMIT", ""]
            r = subprocess.run([f"{cmd}-restore", "-w", "--noflush"], input="\n".join(lines), capture_output=True,
                               text=True, timeout=60)
            if r.returncode:
                self.s.error(f"{cmd}-restore: {r.stderr.strip()[:200]}")
                continue
            self._ipt(cmd, "-I", "OUTPUT", "1", "-j", "TEPHRA_INTEL")
            added += len(mine)
        return added

    def allow(self, target: str, port: int | None = None) -> None:
        try:
            fam = ipaddress.ip_network(target, strict=False).version
        except ValueError:
            return
        key = f"{target}:{port or ''}"
        with self.lock:
            if key in self.allowed_ips or not self.s.block:
                return
            for cmd, f in self.families:
                if f == fam:
                    if port:
                        for proto in ("udp", "tcp"):
                            self._ipt(cmd, "-I", "TEPHRA_OUT", "1", "-d", target, "-p", proto, "--dport", str(port),
                                      "-j", "RETURN")
                    else:
                        self._ipt(cmd, "-I", "TEPHRA_OUT", "1", "-d", target, "-j", "RETURN")
            self.allowed_ips.add(key)

    def teardown(self, quiet: bool = False) -> None:
        for cmd, _ in self.families:
            for chain in CHAINS:
                while self._ipt(cmd, "-D", "OUTPUT", "-j", chain, check=False):
                    pass
                self._ipt(cmd, "-F", chain, check=False)
                self._ipt(cmd, "-X", chain, check=False)
            while self._ipt(cmd, "-D", "DOCKER-USER", "-m", "conntrack", "--ctstate", "NEW", "-j", "LOG",
                            "--log-prefix", LOG_FWD, check=False):
                pass


# ---------- sockets -> processes ----------

def _hex_port(local: str) -> int:
    return int(local.rsplit(":", 1)[1], 16)


def socket_inode(proto: str, sport: int) -> str | None:
    for f in (f"/proc/net/{proto}", f"/proc/net/{proto}6"):
        try:
            with open(f) as fh:
                next(fh)
                for line in fh:
                    p = line.split()
                    if _hex_port(p[1]) == sport and p[9] != "0":
                        return p[9]
        except (OSError, StopIteration, IndexError, ValueError):
            continue
    return None


def pid_for_inode(inode: str) -> int | None:
    target = f"socket:[{inode}]"
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            for fd in os.listdir(f"/proc/{pid}/fd"):
                try:
                    if os.readlink(f"/proc/{pid}/fd/{fd}") == target:
                        return int(pid)
                except OSError:
                    continue
        except OSError:
            continue
    return None


def _user(uid: str) -> str | None:
    try:
        import pwd
        return pwd.getpwuid(int(uid)).pw_name
    except (KeyError, ValueError, ImportError):
        return None


def proc_info(pid: int) -> dict:
    info: dict = {"pid": pid}
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            argv = [a.decode("utf-8", "replace") for a in f.read().split(b"\0") if a]
        info["argv"] = redact(" ".join(argv))[:400]
        info["exe"] = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        pass
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("Name:"):
                    info["comm"] = line.split(None, 1)[1].strip()
                elif line.startswith("PPid:"):
                    info["ppid"] = int(line.split()[1])
                    break
    except OSError:
        pass
    if info.get("ppid"):
        try:
            with open(f"/proc/{info['ppid']}/comm") as f:
                info["parent"] = f.read().strip()
        except OSError:
            pass
    return info


# ---------- sensor ----------

class Sensor:
    def __init__(self) -> None:
        env = os.environ
        self.dir = env.get("TEPHRA_DIR") or os.path.join(env.get("RUNNER_TEMP", "/tmp"), "tephra-sensor")
        os.makedirs(self.dir, exist_ok=True)
        self.mode = (env.get("TEPHRA_MODE") or "audit").lower()
        self.block = self.mode == "block"
        self.console = (env.get("TEPHRA_CONSOLE_URL") or "").rstrip("/")
        self.token = env.get("TEPHRA_INGEST_TOKEN") or ""
        # without an ingest token, the sensor proves itself to the console with the job's own GitHub OIDC token
        self.oidc_url = env.get("ACTIONS_ID_TOKEN_REQUEST_URL") or ""
        self.oidc_request = env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN") or ""
        self._oidc: tuple[str, float] | None = None
        self.run_id = env.get("GITHUB_RUN_ID", "")
        self.repo = env.get("GITHUB_REPOSITORY", "")
        user = split_list(env.get("TEPHRA_ALLOWED", ""))
        extra = [re.sub(r"^https?://", "", self.console).split("/")[0].split(":")[0]] if self.console else []
        self.allow = Allowlist(RUNNER_ENDPOINTS + user + extra)
        self.user_allowed = user
        self.listen = addr(env.get("TEPHRA_DNS_LISTEN") or "127.0.0.1:53")
        self.rewrite_resolv = (env.get("TEPHRA_REWRITE_RESOLV") or "true").lower() != "false"
        self.workspace = env.get("TEPHRA_WORKSPACE") or env.get("GITHUB_WORKSPACE") or ""
        self.upstreams = [addr(u) for u in split_list(env.get("TEPHRA_DNS_UPSTREAM", ""))] or self._resolvers()
        self.ip_names: dict[str, str] = {}
        self.aliases: set[str] = set()            # CNAME targets of allowed names
        self.records: dict[str, dict] = {}       # deduplicated, for the console
        self.pending: list[dict] = []            # not yet streamed
        self.errors: list[str] = []
        self.raw_count = 0
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.fw = Firewall(self)
        self.intel_on = (env.get("TEPHRA_INTEL") or "on").strip().lower() not in ("off", "false", "no", "0")
        self.bad = KnownBad([])                  # known-bad domains (their networks go to the firewall)
        self.intel_source = None
        self.actions: list[str] = []
        self.raw = open(os.path.join(self.dir, "events.jsonl"), "a")

    # ----- output -----
    def error(self, msg: str) -> None:
        with self.lock:
            if len(self.errors) < 50:
                self.errors.append(msg)
        print(f"tephra-sensor: {msg}", file=sys.stderr, flush=True)

    def emit(self, rec: dict, key: str) -> None:
        rec = {"time": now(), **rec}
        with self.lock:
            if self.raw_count < MAX_RAW:
                self.raw.write(json.dumps(rec) + "\n")
                self.raw.flush()
                self.raw_count += 1
            if key in self.records:
                r = self.records[key]
                r["count"] = r.get("count", 1) + 1
                if rec.get("domain") and not r.get("domain"):
                    r["domain"] = rec["domain"]
                times = r.setdefault("times", [r["time"]])
                if r.get("type") == "egress" and len(times) < MAX_TIMES and _secs(times[-1], rec["time"]) >= TIME_SPACING_S:
                    times.append(rec["time"])
                    self.pending.append({"key": r["key"], "update": True, "type": r["type"], "time": r["time"],
                                         "times": [rec["time"]]})
                return
            rec["count"] = 1
            rec["key"] = hashlib.sha256(f"{self.run_id}:{key}".encode()).hexdigest()[:24]
            self.records[key] = rec
            self.pending.append(rec)

    # ----- DNS -----
    def _resolvers(self) -> list[tuple[str, int]]:
        out = []
        try:
            with open("/etc/resolv.conf") as f:
                out = [addr(line.split()[1]) for line in f if line.startswith("nameserver") and len(line.split()) > 1]
        except OSError:
            pass
        return [u for u in out if u != self.listen] or [("127.0.0.53", 53)]

    def _forward(self, q: bytes, tcp: bool = False) -> bytes | None:
        for host, port in self.upstreams:
            fam = socket.AF_INET6 if ":" in host else socket.AF_INET
            try:
                if tcp:
                    with socket.create_connection((host, port), timeout=4) as c:
                        c.sendall(struct.pack(">H", len(q)) + q)
                        n = struct.unpack(">H", self._recv_exact(c, 2))[0]
                        return self._recv_exact(c, n)
                with socket.socket(fam, socket.SOCK_DGRAM) as u:
                    u.settimeout(3)
                    u.sendto(q, (host, port))
                    return u.recv(65535)
            except (OSError, struct.error):
                continue
        return None

    @staticmethod
    def _recv_exact(c: socket.socket, n: int) -> bytes:
        b = b""
        while len(b) < n:
            chunk = c.recv(n - len(b))
            if not chunk:
                raise OSError("closed")
            b += chunk
        return b

    def answer(self, q: bytes, tcp: bool = False) -> bytes | None:
        try:
            name, qtype, _ = parse_query(q)
        except (IndexError, ValueError, struct.error):
            return None
        allowed = self.allow.domain(name) or name in self.aliases
        if self.intel_on and self.bad.domain(name) and not CORE.domain(name):
            self.emit({"type": "dns_blocked", "domain": name, "qtype": qtype, "reason": "threat_intel"},
                      f"dnsblock:{name}")
            return nxdomain(q)
        if self.block and not allowed:
            self.emit({"type": "dns_blocked", "domain": name, "qtype": qtype}, f"dnsblock:{name}")
            return nxdomain(q)
        r = self._forward(q, tcp)
        if r is None:
            return None
        try:
            answers = parse_answers(r)
        except (IndexError, ValueError, struct.error):
            answers = []
        if allowed:
            # an allowed name that is an alias (CNAME) of another name, as with load balancers and CDNs: the
            # resolver may look the target up on its own, so the target is allowed too, unless it is known-bad
            for _, t, target in answers:
                target = target.lower().rstrip(".")
                if t == 5 and target not in self.aliases and not (self.intel_on and self.bad.domain(target)):
                    self.aliases.add(target)
        ips = [v for _, t, v in answers if t in (1, 28)]
        for ip in ips:
            self.ip_names[ip] = name
            if allowed:
                self.fw.allow(ip)      # before the client gets the address, so its connection is let through
        if ips:
            self.emit({"type": "dns", "domain": name, "ips": ips[:8]}, f"dns:{name}")
        return r

    def dns_udp(self) -> None:
        fam = socket.AF_INET6 if ":" in self.listen[0] else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(self.listen)
        s.settimeout(0.5)
        self.ready_dns.set()
        while not self.stop_event.is_set():
            try:
                q, client = s.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=lambda q=q, c=client: self._udp_reply(s, q, c), daemon=True).start()

    def _udp_reply(self, s: socket.socket, q: bytes, client) -> None:
        r = self.answer(q)
        if r:
            try:
                s.sendto(r, client)
            except OSError:
                pass

    def dns_tcp(self) -> None:
        fam = socket.AF_INET6 if ":" in self.listen[0] else socket.AF_INET
        s = socket.socket(fam, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(self.listen)
        s.listen(32)
        s.settimeout(0.5)
        while not self.stop_event.is_set():
            try:
                c, _ = s.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._tcp_client, args=(c,), daemon=True).start()

    def _tcp_client(self, c: socket.socket) -> None:
        with c:
            try:
                c.settimeout(5)
                n = struct.unpack(">H", self._recv_exact(c, 2))[0]
                r = self.answer(self._recv_exact(c, n), tcp=True)
                if r:
                    c.sendall(struct.pack(">H", len(r)) + r)
            except (OSError, struct.error):
                pass

    def set_resolver(self) -> None:
        if not self.rewrite_resolv:
            return
        path = "/etc/resolv.conf"
        backup = os.path.join(self.dir, "resolv.backup.json")
        if os.path.exists(backup):
            return
        state = {"symlink": os.readlink(path) if os.path.islink(path) else None}
        with open(path) as f:
            state["content"] = f.read()
        with open(backup, "w") as f:
            json.dump(state, f)
        keep = [ln for ln in state["content"].splitlines() if ln.startswith(("search", "options"))]
        os.remove(path)
        with open(path, "w") as f:
            f.write(f"# tephra-sensor\nnameserver {self.listen[0]}\n" + "\n".join(keep) + "\n")

    def restore_resolver(self) -> None:
        backup = os.path.join(self.dir, "resolv.backup.json")
        if not os.path.exists(backup):
            return
        with open(backup) as f:
            state = json.load(f)
        path = "/etc/resolv.conf"
        try:
            os.remove(path)
        except OSError:
            pass
        if state.get("symlink"):
            os.symlink(state["symlink"], path)
        else:
            with open(path, "w") as f:
                f.write(state["content"])
        os.remove(backup)

    # ----- connections (iptables LOG -> kernel log) -----
    KV = re.compile(r"(\w+)=(\S*)")

    def kernel_log(self) -> None:
        try:
            fd = os.open("/dev/kmsg", os.O_RDONLY)
            os.lseek(fd, 0, os.SEEK_END)
        except OSError as e:
            self.error(f"can't read the kernel log ({e}); connections aren't recorded")
            return
        while not self.stop_event.is_set():
            try:
                line = os.read(fd, 8192).decode("utf-8", "replace")
            except BrokenPipeError:      # older records were overwritten; carry on
                continue
            except OSError:
                break
            msg = line.split(";", 1)[-1]
            for prefix, kind in ((LOG_NEW, "egress"), (LOG_BLOCK, "blocked"), (LOG_FWD, "container"),
                                 (LOG_INTEL, "intel")):
                if prefix in msg:
                    self.connection(dict(self.KV.findall(msg)), kind)
                    break

    def connection(self, f: dict, kind: str) -> None:
        dst, proto = f.get("DST", ""), (f.get("PROTO") or "").lower()
        if kind == "egress" and f.get("DPT") == "53" and dst in {h for h, _ in self.upstreams}:
            return     # our own forwarded DNS
        port = int(f.get("DPT") or 0)
        info: dict = {}
        if kind != "container" and proto in ("tcp", "udp") and f.get("SPT"):
            inode = socket_inode(proto, int(f["SPT"]))
            pid = pid_for_inode(inode) if inode else None
            if pid:
                info = proc_info(pid)
        domain = self.ip_names.get(dst)
        rec = {"type": "egress", "ip": dst, "port": port, "proto": proto, "domain": domain,
               "uid": f.get("UID"), "process": info.get("comm") or ("container" if kind == "container" else None),
               "exe": info.get("exe"), "argv": info.get("argv"), "pid": info.get("pid"),
               "blocked": kind in ("blocked", "intel"),
               "allowed": bool(domain and (self.allow.domain(domain) or domain in self.aliases)) or self.allow.ip(dst)}
        if kind == "intel":
            rec["reason"] = "threat_intel"
            kind = "blocked_intel"
        if not rec["process"] and f.get("UID"):
            rec["process"] = f"uid {f['UID']}" + (f" ({_user(f['UID'])})" if _user(f["UID"]) else "")
        if kind == "blocked":
            # the same connection was logged as new a moment earlier: mark that record instead of adding one
            with self.lock:
                hits = [r for k, r in self.records.items() if k.startswith(f"egress:{domain or dst}:{port}:")]
                for r in hits:
                    if not r.get("blocked"):
                        r["blocked"] = True
                        self.pending.append({**r, "update": True})
            if hits:
                return
        who = info.get("exe") or rec["process"]
        self.emit(rec, f"egress:{domain or dst}:{port}:{who}")

    # ----- processes (netlink proc connector) -----
    def processes(self) -> None:
        try:
            s = socket.socket(socket.AF_NETLINK, socket.SOCK_DGRAM, 11)   # NETLINK_CONNECTOR
            s.bind((0, 1))                                                  # CN_IDX_PROC
            op = struct.pack("I", 1)                                        # PROC_CN_MCAST_LISTEN
            cn = struct.pack("IIIIHH", 1, 1, 0, 0, len(op), 0) + op
            s.send(struct.pack("IHHII", 16 + len(cn), 3, 0, 0, os.getpid()) + cn)
            s.settimeout(0.5)
        except OSError as e:
            self.error(f"process events unavailable ({e}); processes aren't recorded")
            return
        me = os.getpid()
        while not self.stop_event.is_set():
            try:
                data = s.recv(65536)
            except socket.timeout:
                continue
            except OSError:
                break
            off = 0
            while off + 60 <= len(data):
                length = struct.unpack("I", data[off:off + 4])[0] or len(data)
                what = struct.unpack("I", data[off + 36:off + 40])[0]
                if what == 2:                                        # PROC_EVENT_EXEC
                    tgid = struct.unpack("I", data[off + 56:off + 60])[0]
                    if tgid != me:
                        info = proc_info(tgid)
                        if info.get("ppid") == me:
                            pass      # the sensor's own iptables/git calls
                        elif info.get("exe") or info.get("argv"):
                            argv = info.get("argv") or ""
                            first = argv.split(" ")[:2]
                            self.emit({"type": "exec", "exe": info.get("exe"), "argv": argv, "pid": tgid,
                                       "parent": info.get("parent")},
                                      f"exec:{info.get('exe') or first[0]}:{' '.join(first[1:])[:60]}")
                off += (length + 3) & ~3

    # ----- source files -----
    def changed_files(self) -> None:
        ws = self.workspace
        if not ws or not os.path.isdir(os.path.join(ws, ".git")):
            return
        try:
            out = subprocess.run(["git", "-c", "safe.directory=*", "-C", ws, "status", "--porcelain",
                                  "--untracked-files=no"], capture_output=True, text=True, timeout=60).stdout
        except (OSError, subprocess.SubprocessError) as e:
            self.error(f"git status failed: {e}")
            return
        for line in out.splitlines():
            code, path = line[:2].strip(), line[3:]
            change = {"M": "modified", "D": "deleted", "R": "renamed", "A": "added", "T": "type changed"}.get(code[:1], code)
            self.emit({"type": "file_modified", "path": path, "change": change}, f"file:{path}")

    # ----- packages installed during the job -----
    def list_packages(self) -> None:
        """npm packages (from npm's own record of what's in node_modules), Python packages written during the job,
        and apt packages installed or upgraded since the sensor started. Names and versions only."""
        since = getattr(self, "start_epoch", 0.0)
        count = 0

        def add(eco: str, name: str, version: str, **extra) -> None:
            nonlocal count
            if count >= MAX_PACKAGES or not name or not version:
                return
            count += 1
            self.emit({"type": "package", "ecosystem": eco, "name": name, "version": version, **extra},
                      f"pkg:{eco}:{name}@{version}")

        visited = 0
        for root in [d for d in (self.workspace, os.path.expanduser("~runner")) if d and os.path.isdir(d)]:
            for dirpath, dirnames, filenames in os.walk(root):
                visited += 1
                if visited > 50000:
                    break
                depth = dirpath[len(root):].count(os.sep)
                if "node_modules" in dirnames:
                    lock = os.path.join(dirpath, "node_modules", ".package-lock.json")
                    try:
                        with open(lock) as f:
                            pkgs = json.load(f).get("packages") or {}
                    except (OSError, ValueError):
                        pkgs = {}
                    for path, meta in pkgs.items():
                        if not path or meta.get("link") or "node_modules/" not in path:
                            continue
                        add("npm", meta.get("name") or path.rsplit("node_modules/", 1)[-1], meta.get("version") or "",
                            install_script=bool(meta.get("hasInstallScript")))
                if dirpath.endswith(("site-packages", "dist-packages")):
                    self._python_dists(dirpath, since, add)
                    dirnames[:] = []
                    continue
                dirnames[:] = [d for d in dirnames if d not in ("node_modules", ".git") and depth < 8]
        for pattern in ("/opt/hostedtoolcache/Python/*/*/lib/python3*/site-packages",
                        "/usr/local/lib/python3*/dist-packages", "/usr/lib/python3/dist-packages"):
            for d in glob.glob(pattern):
                self._python_dists(d, since, add)
        try:
            with open("/var/log/dpkg.log", errors="replace") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 6 and parts[2] in ("install", "upgrade"):
                        try:
                            at = dt.datetime.strptime(f"{parts[0]} {parts[1]}", "%Y-%m-%d %H:%M:%S")
                        except ValueError:
                            continue
                        if at.replace(tzinfo=dt.timezone.utc).timestamp() >= since - 1:
                            add("Debian", parts[3].split(":")[0], parts[5])
        except OSError:
            pass

    @staticmethod
    def _python_dists(site: str, since: float, add) -> None:
        for info in glob.glob(os.path.join(site, "*.dist-info")):
            try:
                if os.stat(info).st_mtime < since - 1:
                    continue                      # there before the job: not installed by it
                name = version = ""
                with open(os.path.join(info, "METADATA"), errors="replace") as f:
                    for line in f:
                        if line.startswith("Name:"):
                            name = line[5:].strip()
                        elif line.startswith("Version:"):
                            version = line[8:].strip()
                        elif not line.strip():
                            break
                add("PyPI", name, version)
            except OSError:
                continue

    # ----- threat intel -----
    def allow_console(self) -> None:
        """In block mode, let the sensor reach its console before the DNS proxy (which normally opens allowed
        addresses as they're looked up) is running: needed for the threat-intel list fetched at start."""
        host = re.sub(r"^https?://", "", self.console).split("/")[0].split(":")[0] if self.console else ""
        if not (self.block and host):
            return
        try:
            infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP, flags=socket.AI_CANONNAME)
        except OSError as e:
            self.error(f"couldn't look up the console {host} ({e}); its threat-intel list may be unavailable")
            return
        for info in infos:
            canon = (info[3] or "").lower().rstrip(".")
            if canon and canon != host.lower():
                # the console is an alias (e.g. of a load balancer); the runner's resolver now remembers that, and
                # will later ask the DNS proxy for the target name directly, so allow it too
                self.aliases.add(canon)
            ip = info[4][0]
            self.ip_names[ip] = host
            self.fw.allow(ip)

    def auth(self) -> str | None:
        """Authorization header for the console: the ingest token, else a fresh OIDC token for this job (cached
        until a minute before it expires), else None."""
        if self.token:
            return f"Bearer {self.token}"
        if not (self.oidc_url and self.oidc_request):
            return None
        if self._oidc and self._oidc[1] - time.time() > 60:
            return f"Bearer {self._oidc[0]}"
        sep = "&" if "?" in self.oidc_url else "?"
        req = urllib.request.Request(f"{self.oidc_url}{sep}audience={OIDC_AUDIENCE}",
                                     headers={"Authorization": f"bearer {self.oidc_request}"})
        try:
            jwt = json.loads(urllib.request.urlopen(req, timeout=8).read())["value"]
            claims = json.loads(base64.urlsafe_b64decode(jwt.split(".")[1] + "=="))
            self._oidc = (jwt, float(claims.get("exp", time.time() + 300)))
            return f"Bearer {jwt}"
        except Exception as e:  # noqa: BLE001 - streaming is optional; the artifact still carries everything
            self.error(f"couldn't get a GitHub OIDC token for the console ({str(e)[:100]}); add id-token: write "
                       "to the job, or set ingest-token")
            return None

    def load_intel(self) -> None:
        """Known-bad domains and IPs: from the console when it's set, else straight from public feeds."""
        if not self.intel_on:
            return
        domains: list[str] = []
        nets: list[str] = []
        auth = self.auth() if self.console else None
        if auth:
            try:
                req = urllib.request.Request(f"{self.console}/api/intel/blocklist", headers={"Authorization": auth})
                body = json.loads(urllib.request.urlopen(req, timeout=8).read())
                if not body.get("block"):
                    self.intel_source = "off in Tephra Trace"
                    return
                domains, nets = body.get("domains") or [], body.get("ips") or []
                self.intel_source = "Tephra Trace"
            except Exception as e:  # noqa: BLE001 - fall back to public feeds
                self.error(f"couldn't get the threat-intel list from the console ({str(e)[:100]}); using public feeds")
        if self.intel_source is None:
            for name, url in PUBLIC_FEEDS.items():
                try:
                    text = urllib.request.urlopen(urllib.request.Request(url, headers={"User-Agent": "tephra-sensor"}),
                                                  timeout=6).read().decode("utf-8", "replace")
                except Exception as e:  # noqa: BLE001
                    self.error(f"threat-intel feed {name} unavailable ({str(e)[:80]})")
                    continue
                if name == "feodo":
                    try:
                        nets += [r.get("ip_address", "") for r in json.loads(text)]
                    except ValueError:
                        pass
                else:
                    for line in text.splitlines():
                        try:
                            nets.append(json.loads(line).get("cidr", ""))
                        except (ValueError, AttributeError):
                            pass
            self.intel_source = "public feeds" if nets else None
        safe = []
        for n in nets:
            try:
                net = ipaddress.ip_network(n.strip(), strict=False)
            except (ValueError, AttributeError):
                continue
            if net.is_global and not any(net.overlaps(ipaddress.ip_network(p)) for p in PLATFORM_IPS):
                safe.append(str(net))
        self.bad = KnownBad([d for d in domains if d and not CORE.domain(d)])
        n = self.fw.deny_known_bad(safe) if safe else 0
        if self.intel_source:
            self.emit({"type": "sensor", "event": "threat_intel", "source": self.intel_source,
                       "domains": len(self.bad.domains), "networks": n}, "sensor:intel")

    def list_actions(self) -> None:
        """owner/repo@ref of every action the runner downloaded for this job."""
        ws = os.environ.get("GITHUB_WORKSPACE") or ""
        root = os.path.join(os.path.dirname(os.path.dirname(ws)), "_actions") if ws else ""
        if not root or not os.path.isdir(root):
            return
        out = []
        try:
            for owner in sorted(os.listdir(root)):
                for repo in sorted(os.listdir(os.path.join(root, owner))):
                    d = os.path.join(root, owner, repo)
                    if not os.path.isdir(d):
                        continue
                    for ref in sorted(os.listdir(d)):
                        if os.path.isdir(os.path.join(d, ref)) and not ref.endswith(".completed"):
                            out.append(f"{owner}/{repo}@{ref}")
        except OSError as e:
            self.error(f"couldn't list the job's actions: {e}")
        self.actions = out[:500]

    # ----- streaming -----
    def stream(self, final: bool = False) -> None:
        if not (self.console and self.run_id and (self.token or (self.oidc_url and self.oidc_request))):
            return
        while not self.stop_event.is_set() or final:
            with self.lock:
                batch, self.pending = self.pending[:500], self.pending[500:]
            if batch:
                payload = {"run_id": self.run_id, "repo": self.repo, "records": batch}
                if final and self.actions:
                    payload["actions"] = self.actions
                body = json.dumps(payload).encode()
                try:
                    auth = self.auth()
                    if not auth:
                        raise RuntimeError("no credential for the console")
                    req = urllib.request.Request(f"{self.console}/api/ingest/sensor", data=body, method="POST",
                                                 headers={"Authorization": auth, "Content-Type": "application/json"})
                    urllib.request.urlopen(req, timeout=8).read()
                except Exception as e:  # noqa: BLE001 - never fail the build over streaming
                    self.error(f"couldn't reach the console: {str(e)[:120]}")
                    with self.lock:
                        self.pending = batch + self.pending
                    if final:
                        return
            if final and not self.pending:
                return
            if not final:
                self.stop_event.wait(3)

    # ----- lifecycle -----
    def run(self, ready_file: str | None = None) -> None:
        self.ready_dns = threading.Event()
        self.started = now()
        self.start_epoch = time.time()
        signal.signal(signal.SIGTERM, lambda *_: self.stop_event.set())
        signal.signal(signal.SIGINT, lambda *_: self.stop_event.set())
        threads = [threading.Thread(target=t, daemon=True) for t in
                   (self.dns_udp, self.dns_tcp, self.kernel_log, self.processes, self.stream)]
        dns_ips = [h for h, _ in self.upstreams if not ipaddress.ip_address(h).is_loopback] \
            if all(self._is_ip(h) for h, _ in self.upstreams) else []
        try:
            self.fw.setup(self.block, PLATFORM_IPS + [str(n) for n in self.allow.nets], dns_ips)
            self.allow_console()                 # the DNS proxy isn't up yet, so open the console's addresses now
            self.load_intel()
            for t in threads:
                t.start()
            if not self.ready_dns.wait(5):
                raise RuntimeError(f"DNS proxy couldn't listen on {self.listen[0]}:{self.listen[1]}")
            self.set_resolver()
            self.emit({"type": "sensor", "event": "started", "mode": self.mode, "version": VERSION,
                       "allowed": self.user_allowed}, "sensor:start")
            self.emit({"type": "host", **host_facts(dict(os.environ))}, "host")
        except Exception as e:  # noqa: BLE001
            self.error(f"setup failed: {e}")
            self.cleanup()
            raise
        if ready_file:
            with open(ready_file, "w") as f:
                f.write(str(os.getpid()))
        while not self.stop_event.is_set():
            time.sleep(0.2)
        time.sleep(0.3)   # let the last kernel-log lines arrive
        self.finish()

    @staticmethod
    def _is_ip(h: str) -> bool:
        try:
            ipaddress.ip_address(h)
            return True
        except ValueError:
            return False

    def cleanup(self) -> None:
        self.restore_resolver()
        self.fw.teardown(quiet=True)

    def finish(self) -> None:
        self.cleanup()
        self.changed_files()
        self.list_actions()
        try:
            self.list_packages()
        except Exception as e:  # noqa: BLE001 - the inventory must never cost the job its other records
            self.error(f"package inventory failed: {e}")
        self.emit({"type": "sensor", "event": "stopped", "mode": self.mode,
                   "records": len(self.records), "raw_events": self.raw_count}, "sensor:stop")
        self.stream(final=True)
        records = list(self.records.values())
        summary = {"version": VERSION, "run_id": self.run_id, "repo": self.repo, "mode": self.mode,
                   "started": self.started, "stopped": now(), "records": records, "errors": self.errors,
                   "actions": self.actions, "threat_intel": self.intel_source}
        with open(os.path.join(self.dir, "summary.json"), "w") as f:
            json.dump(summary, f, indent=1)
        write_step_summary(summary)
        self.raw.close()


def write_step_summary(summary: dict) -> None:
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        return
    recs = summary["records"]
    egress = [r for r in recs if r["type"] == "egress"]
    blocked = [r for r in recs if r["type"] == "dns_blocked" or r.get("blocked")]
    domains = sorted({r["domain"] for r in egress if r.get("domain") and not r.get("blocked")})
    pkgs = [r for r in recs if r["type"] == "package"]
    lines = [f"### Runner sensor ({summary['mode']} mode)", "",
             f"{len(egress)} outbound endpoints, {sum(r['type'] == 'exec' for r in recs)} distinct programs, "
             f"{sum(r['type'] == 'file_modified' for r in recs)} source files changed, {len(blocked)} blocked, "
             f"{len(pkgs)} packages installed ({sum(bool(r.get('install_script')) for r in pkgs)} with install "
             "scripts).", ""]
    if egress:
        lines += ["| Destination | Port | Process | Count | |", "|---|---|---|---|---|"]
        for r in sorted(egress, key=lambda r: (r.get("domain") or r["ip"]))[:60]:
            state = "blocked" if r.get("blocked") else ("allowed" if r.get("allowed") else "")
            lines.append(f"| `{r.get('domain') or r['ip']}` | {r['port']} | {r.get('process') or ''} | {r['count']} | {state} |")
    for r in blocked:
        why = " (known-bad: threat intel)" if r.get("reason") == "threat_intel" else ""
        if r["type"] == "dns_blocked":
            lines.append(f"\nBlocked lookup: `{r['domain']}`{why}")
        elif why:
            lines.append(f"\nBlocked connection: `{r.get('domain') or r.get('ip')}`{why}")
    if domains:
        lines += ["", "Allowlist for block mode:", "```yaml", "allowed-endpoints: |"] + \
                 [f"  {d}" for d in domains] + ["```"]
    with open(path, "a") as f:
        f.write("\n".join(lines) + "\n")


# ---------- commands ----------

def cmd_start() -> int:
    s_dir = Sensor().dir
    ready = os.path.join(s_dir, "ready")
    for f in (ready,):
        if os.path.exists(f):
            os.remove(f)
    pid = os.fork()
    if pid:
        for _ in range(100):
            if os.path.exists(ready):
                print(f"tephra-sensor: running (pid {open(ready).read()}) in {os.environ.get('TEPHRA_MODE', 'audit')} mode")
                return 0
            done, status = os.waitpid(pid, os.WNOHANG)
            if done:
                print("tephra-sensor: failed to start; see sensor.log", file=sys.stderr)
                try:
                    print(open(os.path.join(s_dir, "sensor.log")).read()[-2000:], file=sys.stderr)
                except OSError:
                    pass
                return 1
            time.sleep(0.1)
        print("tephra-sensor: still starting after 10 s", file=sys.stderr)
        return 1
    os.setsid()
    log = os.open(os.path.join(s_dir, "sensor.log"), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    os.dup2(log, 1)
    os.dup2(log, 2)
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    try:
        Sensor().run(ready_file=ready)
    except Exception:  # noqa: BLE001
        os._exit(1)
    os._exit(0)


def cmd_stop() -> int:
    s = Sensor()
    ready = os.path.join(s.dir, "ready")
    try:
        pid = int(open(ready).read())
        os.kill(pid, signal.SIGTERM)
        for _ in range(300):
            if not os.path.exists(f"/proc/{pid}") or open(f"/proc/{pid}/stat").read().split()[2] == "Z":
                break
            time.sleep(0.1)
        else:
            print("tephra-sensor: didn't stop in 30 s; cleaning up", file=sys.stderr)
            s.cleanup()
    except (OSError, ValueError):
        print("tephra-sensor: not running; cleaning up", file=sys.stderr)
        s.cleanup()
    try:
        os.remove(ready)
    except OSError:
        pass
    path = os.path.join(s.dir, "summary.json")
    if os.path.exists(path):
        summary = json.load(open(path))
        leases = read_wlc_leases()
        if leases:
            summary["wlc_leases"] = leases
            with open(path, "w") as f:
                json.dump(summary, f)
            print(f"tephra-sensor: {len(leases)} Workload Credentials lease(s) reported")
        n = len(summary["records"])
        print(f"tephra-sensor: stopped; {n} records in {path}")
    return 0


# Optional, for brokered credentials (e.g. BeyondTrust Workload Credentials): the job writes one line per credential
# it receives to $RUNNER_TEMP/tephra-wlc-leases: "<leaseId> <sha256 of the access key ID>" (no secrets). Tephra Trace
# uses it to tie the brokered credential to this run exactly.
WLC_LEASES_FILE = "tephra-wlc-leases"
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")


def read_wlc_leases() -> list[dict]:
    lines: list[str] = []
    for name in (WLC_LEASES_FILE,):
        try:
            lines += open(os.path.join(os.environ.get("RUNNER_TEMP") or "/tmp", name)).read().splitlines()[:200]
        except OSError:
            pass
    out = []
    for line in lines:
        lease = key = ""
        for part in line.split():
            if _UUID.match(part):
                lease = part.lower()
            elif _HEX64.match(part):
                key = part.lower()
        if lease or key:
            out.append({"lease_id": lease, "key_sha256": key})
    return out


def load_env_file(argv: list[str]) -> list[str]:
    """The action passes its settings in a file (sudo may drop the environment); load and delete it."""
    if "--env-file" not in argv:
        return argv
    i = argv.index("--env-file")
    path = argv[i + 1] if i + 1 < len(argv) else ""
    try:
        with open(path) as f:
            os.environ.update({k: str(v) for k, v in json.load(f).items()})
        os.remove(path)
    except (OSError, ValueError) as e:
        print(f"tephra-sensor: couldn't read settings file: {e}", file=sys.stderr)
    return argv[:i] + argv[i + 2:]


if __name__ == "__main__":
    sys.argv = load_env_file(sys.argv)
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if os.geteuid() != 0:
        print("tephra-sensor needs root (run it with sudo).", file=sys.stderr)
        sys.exit(1)
    if cmd == "start":
        sys.exit(cmd_start())
    if cmd == "stop":
        sys.exit(cmd_stop())
    Sensor().run(ready_file=os.environ.get("TEPHRA_READY_FILE"))
