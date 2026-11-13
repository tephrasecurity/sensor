"""Unit tests for the parts of the sensor that don't need root: matching, DNS parsing, redaction, reporting."""
import json
import os
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import sensor  # noqa: E402


def query(name: str, qtype: int = 1) -> bytes:
    q = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    for label in name.split("."):
        q += bytes([len(label)]) + label.encode()
    return q + b"\x00" + struct.pack(">HH", qtype, 1)


def test_allowlist():
    a = sensor.Allowlist(["*.amazonaws.com", "api.example.com", "10.0.0.0/8", "registry.npmjs.org:443"])
    assert a.domain("s3.us-east-1.amazonaws.com") and a.domain("amazonaws.com")
    assert a.domain("API.example.com.") and not a.domain("evil-api.example.com")
    assert a.domain("registry.npmjs.org") and a.ip("10.2.3.4") and not a.ip("11.0.0.1")


def test_known_bad_covers_subdomains_but_core_platforms_never():
    bad = sensor.KnownBad(["evil.example.net"])
    assert bad.domain("x.evil.example.net") and bad.domain("evil.example.net") and not bad.domain("example.net")
    assert sensor.CORE.domain("objects.githubusercontent.com") and sensor.CORE.domain("s3.amazonaws.com")


def test_dns_parsing_and_nxdomain():
    q = query("Example.COM")
    name, qtype, end = sensor.parse_query(q)
    assert (name, qtype, end) == ("example.com", 1, len(q))
    r = sensor.nxdomain(q)
    flags = struct.unpack(">H", r[2:4])[0]
    assert flags & 0x8000 and flags & 0xF == 3 and r[:2] == q[:2]


def test_redaction():
    s = sensor.redact("curl -H 'Authorization: Bearer abc.def' https://u:p@host/x --token ghp_" + "a" * 36
                      + " AKIA" + "B" * 16 + " password=hunter2")
    assert "abc.def" not in s and "u:p@" not in s and "ghp_" not in s and "AKIA" not in s and "hunter2" not in s


def test_known_bad_name_refused_in_audit_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("TEPHRA_DIR", str(tmp_path))
    monkeypatch.setenv("TEPHRA_MODE", "audit")
    s = sensor.Sensor()
    s.bad = sensor.KnownBad(["evil.example.net"])
    s._forward = lambda q, tcp=False: (_ for _ in ()).throw(AssertionError("must not resolve"))
    r = s.answer(query("cdn.evil.example.net"))
    assert struct.unpack(">H", r[2:4])[0] & 0xF == 3
    rec = next(x for x in s.records.values() if x["type"] == "dns_blocked")
    assert rec["reason"] == "threat_intel"


def test_lists_the_jobs_actions(tmp_path, monkeypatch):
    work = tmp_path / "work"
    for p in ("_actions/actions/checkout/v4", "_actions/tj-actions/changed-files/v46", "repo/repo"):
        (work / p).mkdir(parents=True)
    monkeypatch.setenv("TEPHRA_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("GITHUB_WORKSPACE", str(work / "repo" / "repo"))
    s = sensor.Sensor()
    s.list_actions()
    assert s.actions == ["actions/checkout@v4", "tj-actions/changed-files@v46"]


def test_lease_report_never_holds_secrets(tmp_path, monkeypatch):
    monkeypatch.setenv("RUNNER_TEMP", str(tmp_path))
    (tmp_path / "tephra-wlc-leases").write_text("0b9d7a3e-5f7a-4c1e-9d3b-2a1f0e9c8b7a " + "a" * 64 + "\nnot-a-lease\n")
    assert sensor.read_wlc_leases() == [{"lease_id": "0b9d7a3e-5f7a-4c1e-9d3b-2a1f0e9c8b7a", "key_sha256": "a" * 64}]


def test_step_summary(tmp_path, monkeypatch):
    out = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(out))
    sensor.write_step_summary({"mode": "audit", "records": [
        {"type": "egress", "domain": "registry.npmjs.org", "ip": "1.2.3.4", "port": 443, "count": 3, "process": "node"},
        {"type": "dns_blocked", "domain": "x.evil.example.net", "reason": "threat_intel"}]})
    text = out.read_text()
    assert "registry.npmjs.org" in text and "threat intel" in text and "allowed-endpoints: |" in text


def test_env_file_is_read_and_deleted(tmp_path):
    f = tmp_path / "s.json"
    f.write_text(json.dumps({"TEPHRA_MODE": "block"}))
    argv = sensor.load_env_file(["sensor.py", "start", "--env-file", str(f)])
    assert argv == ["sensor.py", "start"] and os.environ["TEPHRA_MODE"] == "block" and not f.exists()


def _response(q: bytes, records: list[tuple[str, int, bytes]]) -> bytes:
    """A DNS answer to query q with (owner, type, rdata) records."""
    def enc(n: str) -> bytes:
        return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\x00"
    head = q[:2] + struct.pack(">HHHHH", 0x8180, 1, len(records), 0, 0)
    body = q[12:]
    for owner, rtype, rdata in records:
        body += enc(owner) + struct.pack(">HHIH", rtype, 1, 60, len(rdata)) + rdata
    return head + body


def test_alias_of_an_allowed_name_is_allowed_in_block_mode(tmp_path, monkeypatch):
    monkeypatch.setenv("TEPHRA_DIR", str(tmp_path))
    monkeypatch.setenv("TEPHRA_MODE", "block")
    monkeypatch.setenv("TEPHRA_ALLOWED", "trace.example.com")
    s = sensor.Sensor()
    s.block = True
    s.allow = sensor.Allowlist(["trace.example.com"])
    s.fw = type("FW", (), {"allow": lambda self, ip, port=None: None})()
    lb = "tephra-1.us-east-1.elb.amazonaws.com"

    def fwd(q, tcp=False):
        name, _, _ = sensor.parse_query(q)
        if name == "trace.example.com":     # the resolver gets only the alias and looks the target up itself
            return _response(q, [("trace.example.com", 5,
                                  b"".join(bytes([len(p)]) + p.encode() for p in lb.split(".")) + b"\x00")])
        return _response(q, [(name, 1, bytes([3, 4, 5, 6]))])
    s._forward = fwd
    assert struct.unpack(">H", s.answer(query("trace.example.com"))[2:4])[0] & 0xF == 0
    r = s.answer(query(lb))
    assert struct.unpack(">H", r[2:4])[0] & 0xF == 0                  # the alias target resolves
    assert struct.unpack(">H", s.answer(query("other.amazonaws.com"))[2:4])[0] & 0xF == 3   # others still refused
    s.bad = sensor.KnownBad(["evil.example.net"])
    s.intel_on = True
    s.aliases.clear()
    s._forward = lambda q, tcp=False: _response(q, [("trace.example.com", 5, b"\x04evil\x07example\x03net\x00")])
    s.answer(query("trace.example.com"))
    assert "evil.example.net" not in s.aliases                        # never via a known-bad alias


def test_block_mode_opens_the_console_before_fetching_intel(tmp_path, monkeypatch):
    monkeypatch.setenv("TEPHRA_DIR", str(tmp_path))
    monkeypatch.setenv("TEPHRA_MODE", "block")
    monkeypatch.setenv("TEPHRA_CONSOLE_URL", "https://trace.example.com/")
    s = sensor.Sensor()
    opened = []
    s.fw = type("FW", (), {"allow": lambda self, ip, port=None: opened.append(ip)})()
    monkeypatch.setattr(sensor.socket, "getaddrinfo",
                        lambda host, port, proto=0, flags=0: [(2, 1, 6, "lb-1.elb.amazonaws.com", ("3.4.5.6", 443)),
                                                             (2, 1, 6, "", ("3.4.5.7", 443))])
    s.allow_console()
    assert opened == ["3.4.5.6", "3.4.5.7"] and s.ip_names["3.4.5.6"] == "trace.example.com"
    assert "lb-1.elb.amazonaws.com" in s.aliases                      # the load balancer behind the console
    monkeypatch.setenv("TEPHRA_MODE", "audit")
    a = sensor.Sensor()
    a.fw = s.fw
    opened.clear()
    a.allow_console()
    assert opened == []                          # audit mode never needs it


def test_local_network_traffic_is_neither_logged_nor_blocked(tmp_path, monkeypatch):
    monkeypatch.setenv("TEPHRA_DIR", str(tmp_path))
    monkeypatch.setenv("TEPHRA_MODE", "block")
    s = sensor.Sensor()
    calls = []
    def run(args, **kw):
        calls.append(args)
        fails = "-D" in args or "-L" in args          # nothing to remove yet, no Docker chain
        return type("R", (), {"returncode": 1 if fails else 0, "stderr": ""})()
    monkeypatch.setattr(sensor.subprocess, "run", run)
    s.fw.families = [("iptables", 4), ("ip6tables", 6)]   # as on a runner with IPv6; CI's test job may lack it
    s.fw.setup(True, [], [])
    v6 = [" ".join(a) for a in calls if a[0] == "ip6tables"]
    log_rules, out_rules = [r for r in v6 if " TEPHRA_LOG " in r], [r for r in v6 if " TEPHRA_OUT " in r]
    first_log = next(i for i, r in enumerate(log_rules) if "-j LOG" in r)
    assert any("-d ff00::/8 -j RETURN" in r for r in log_rules[:first_log])      # skipped before it's logged
    block_at = next(i for i, r in enumerate(out_rules) if "-j REJECT" in r)
    assert any("--icmpv6-type 133 -j RETURN" in r for r in out_rules[:block_at])  # router solicitation let out
    assert any("-d 224.0.0.0/4 -j RETURN" in " ".join(a) for a in calls if a[0] == "iptables")


def test_signs_in_with_the_jobs_oidc_token_when_there_is_no_ingest_token(tmp_path, monkeypatch):
    import base64 as b64
    import time as _t
    monkeypatch.setenv("TEPHRA_DIR", str(tmp_path))
    monkeypatch.setenv("TEPHRA_CONSOLE_URL", "https://trace.example.com")
    monkeypatch.delenv("TEPHRA_INGEST_TOKEN", raising=False)
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", "https://run-actions.example/idtoken?api-version=2.0")
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "req-token")
    s = sensor.Sensor()
    exp = int(_t.time()) + 300
    jwt = "eyJhbGciOiJSUzI1NiJ9." + b64.urlsafe_b64encode(json.dumps({"exp": exp}).encode()).decode().rstrip("=") + ".sig"
    seen = []

    class Resp:
        def read(self):
            return json.dumps({"value": jwt}).encode()

    def urlopen(req, timeout=0):
        seen.append((req.full_url, req.headers.get("Authorization")))
        return Resp()
    monkeypatch.setattr(sensor.urllib.request, "urlopen", urlopen)
    assert s.auth() == f"Bearer {jwt}"
    assert seen == [("https://run-actions.example/idtoken?api-version=2.0&audience=tephra-trace", "bearer req-token")]
    assert s.auth() == f"Bearer {jwt}" and len(seen) == 1          # cached until a minute before it expires
    monkeypatch.setenv("TEPHRA_INGEST_TOKEN", "static")
    assert sensor.Sensor().auth() == "Bearer static"               # an ingest token still wins


def test_host_facts(monkeypatch):
    outs = {"dpkg-query": "2.8.3", "apt-config": "R='3'"}
    monkeypatch.setattr(sensor.subprocess, "run", lambda cmd, **kw: type("R", (), {"stdout": outs[cmd[0]]})())
    f = sensor.host_facts({"ImageOS": "ubuntu24", "ImageVersion": "20261102.1"})
    assert f["apt"] == "2.8.3" and f["apt_retries"] == "3" and f["image"] == "ubuntu24 20261102.1"
    assert f.get("os")          # read from /etc/os-release


def test_package_inventory(tmp_path, monkeypatch):
    import time as _t
    ws = tmp_path / "ws"
    (ws / "web" / "node_modules").mkdir(parents=True)
    (ws / "web" / "node_modules" / ".package-lock.json").write_text(json.dumps({"packages": {
        "node_modules/axios": {"version": "1.14.1"},
        "node_modules/plain-crypto-js": {"version": "4.2.1", "hasInstallScript": True},
        "node_modules/@scope/pkg": {"name": "@scope/pkg", "version": "2.0.0"},
        "node_modules/local": {"link": True}, "": {"name": "web"}}}))
    site = ws / ".venv" / "lib" / "python3.12" / "site-packages"
    for name, ver, old in (("litellm", "1.82.8", False), ("requests", "2.32.3", True)):
        d = site / f"{name}-{ver}.dist-info"
        d.mkdir(parents=True)
        (d / "METADATA").write_text(f"Metadata-Version: 2.1\nName: {name}\nVersion: {ver}\n\nbody\n")
        if old:
            os.utime(d, (_t.time() - 3600, _t.time() - 3600))      # there before the job started
    monkeypatch.setenv("TEPHRA_DIR", str(tmp_path / "out"))
    monkeypatch.setenv("GITHUB_WORKSPACE", str(ws))
    monkeypatch.setattr(sensor.glob, "glob", lambda p: [str(x) for x in __import__("glob").iglob(p)]
                        if str(tmp_path) in p else [])
    s = sensor.Sensor()
    s.start_epoch = _t.time() - 60
    s.list_packages()
    pk = {(r["ecosystem"], r["name"], r["version"]): r for r in s.records.values() if r["type"] == "package"}
    assert set(pk) == {("npm", "axios", "1.14.1"), ("npm", "plain-crypto-js", "4.2.1"), ("npm", "@scope/pkg", "2.0.0"),
                       ("PyPI", "litellm", "1.82.8")}
    assert pk[("npm", "plain-crypto-js", "4.2.1")]["install_script"] is True
