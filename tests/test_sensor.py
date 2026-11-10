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
