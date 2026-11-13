#!/usr/bin/env python3
"""tephra-verify: check Tephra Trace evidence offline, without the console.

  tephra-verify report.json [--key signing-key.pem]...     a signed document: evidence pack, incident report, case
  tephra-verify --chain seal-chain.json [--anchors DIR]    the hourly seal chain, optionally against the S3 copies
                                                           (aws s3 sync s3://<bucket>/<prefix>seals/ DIR)

Checks:
- the Ed25519 signature (both formats: v1 over the canonical document, v2 over its SHA-256, used when the key is
  held in AWS KMS);
- that the signing key is one you trust (--key, repeatable: get them from the console's /api/signing-key or from
  `aws kms get-public-key`); without --key it reports the key ID and checks the signature only;
- for incident reports: that every event listed was sealed, by checking its Merkle path to a signed seal;
- for a chain: each seal's signature, that each seal follows the previous one, that the ledger matches each
  seal's root, and that the copies in S3 (written under Object Lock) say the same.

Needs Python 3.9+ and either the `cryptography` package or the `openssl` command (3.0+). Exit code 0 = all good.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile

SIG_V2_PREFIX = b"tephra-signature-v2\n"
GENESIS = "0" * 64


# ---------- the same definitions the console uses ----------

def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha256_hex(data) -> str:
    if not isinstance(data, (bytes, str)):
        data = canonical(data)
    return hashlib.sha256(data.encode() if isinstance(data, str) else data).hexdigest()


def key_id(public_pem: str) -> str:
    return "ed25519:" + sha256_hex(public_pem)[:16]


def leaf_hash(line: str) -> str:
    return hashlib.sha256(b"\x00" + line.encode()).hexdigest()


def node(left: str, right: str) -> str:
    return hashlib.sha256(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right)).hexdigest()


def merkle_root(leaves: list) -> str:
    level = list(leaves)
    if not level:
        return GENESIS
    while len(level) > 1:
        level = [node(level[i], level[i + 1]) if i + 1 < len(level) else level[i] for i in range(0, len(level), 2)]
    return level[0]


def check_proof(line: str, proof: list, root: str) -> bool:
    h = leaf_hash(line)
    for side, sib in proof:
        h = node(sib, h) if side == "L" else node(h, sib)
    return h == root


def leaf_line(row: dict) -> str:
    return f"{row['seq']}|{row['event_id']}|{row.get('sha256') or ''}|{row['op']}|{row.get('reason') or ''}"


# ---------- Ed25519 ----------

def ed25519_verify(public_pem: str, signature: bytes, message: bytes) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import serialization
    except ImportError:
        return _openssl_verify(public_pem, signature, message)
    try:
        serialization.load_pem_public_key(public_pem.encode()).verify(signature, message)
        return True
    except InvalidSignature:
        return False


def _openssl_verify(public_pem: str, signature: bytes, message: bytes) -> bool:
    with tempfile.TemporaryDirectory() as d:
        paths = {n: os.path.join(d, n) for n in ("key.pem", "sig", "msg")}
        for n, data in (("key.pem", public_pem.encode()), ("sig", signature), ("msg", message)):
            with open(paths[n], "wb") as f:
                f.write(data)
        r = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", paths["key.pem"], "-rawin",
                            "-in", paths["msg"], "-sigfile", paths["sig"]], capture_output=True, text=True)
        return r.returncode == 0


def check_signature(doc: dict, trusted: list) -> tuple:
    """(ok, message) for one signed document."""
    try:
        sig, body = doc["signature"], doc["body"]
        pem = sig["public_key"]
        value = base64.b64decode(sig["value"])
    except (KeyError, TypeError, ValueError):
        return False, "not a signed Tephra document"
    if sig.get("scheme") == "sha256-v2":
        digest = sha256_hex(body)
        if digest != sig.get("body_sha256"):
            return False, "the content doesn't match its recorded SHA-256: changed after signing"
        good = ed25519_verify(pem, value, SIG_V2_PREFIX + digest.encode())
    else:
        good = ed25519_verify(pem, value, canonical(body).encode())
    if not good:
        return False, "signature doesn't match the content: changed after signing"
    kid = key_id(pem)
    if trusted and pem.strip() not in [t.strip() for t in trusted]:
        return False, f"valid signature, but by key {kid}, which isn't one of the keys you trust"
    return True, f"valid signature by {kid}" + ("" if trusted else " (pass --key to require a key you trust)")


# ---------- commands ----------

def verify_document(path: str, trusted: list) -> bool:
    doc = json.load(open(path))
    ok, msg = check_signature(doc, trusted)
    body = doc.get("body", {})
    print(f"{'OK  ' if ok else 'FAIL'} {path}: {body.get('type', 'document')}, {msg}")
    proofs = body.get("seal_proofs")
    if ok and proofs:
        seal_roots = {}
        for s in proofs.get("seals", []):
            s_ok, s_msg = check_signature(s, trusted)
            n = s.get("body", {}).get("n")
            if not s_ok:
                print(f"FAIL   seal {n}: {s_msg}")
                ok = False
            seal_roots[n] = s.get("body", {}).get("root")
        events = {e.get("id"): e for e in body.get("events", []) if isinstance(e, dict)}
        bad = 0
        for p in proofs.get("proofs", []):
            line_sha = p["line"].split("|")[2]
            ev = events.get(p["event_id"])
            if not check_proof(p["line"], p["proof"], seal_roots.get(p["seal"], "")):
                print(f"FAIL   event {p['event_id']}: its path doesn't lead to seal {p['seal']}'s root")
                bad += 1
            elif ev is not None and ev.get("sha256") and ev["sha256"] != line_sha:
                print(f"FAIL   event {p['event_id']}: the report's copy differs from what was sealed")
                bad += 1
        n = len(proofs.get("proofs", []))
        print(f"{'OK  ' if not bad else 'FAIL'}   {n - bad} of {n} events proven sealed"
              + (f"; {len(proofs.get('pending', []))} too recent to be sealed when the report was made"
                 if proofs.get("pending") else ""))
        ok = ok and not bad
    return ok


def verify_chain(path: str, trusted: list, anchors: str | None) -> bool:
    data = json.load(open(path))
    trusted = trusted or [k["public_key"] for k in data.get("public_keys", [])]
    ledger = {}
    for r in data.get("ledger", []):
        ledger[r["seq"]] = r
    ok, prev_chain, prev_to, prev_n = True, None, None, None
    for doc in data.get("seals", []):
        b = doc.get("body", {})
        s_ok, msg = check_signature(doc, trusted)
        problems = [] if s_ok else [msg]
        if prev_n is not None:
            if b.get("n") != prev_n + 1:
                problems.append(f"follows seal {prev_n}: seals in between are missing")
            if b.get("prev_chain") != prev_chain:
                problems.append("doesn't chain to the previous seal")
            if b.get("from_seq") != prev_to + 1:
                problems.append("ledger entries between seals were never sealed")
        elif b.get("n") == 1 and b.get("prev_chain") != GENESIS:
            problems.append("first seal doesn't start the chain")
        if hashlib.sha256(bytes.fromhex(b.get("prev_chain", GENESIS)) + bytes.fromhex(b.get("root", GENESIS))
                          ).hexdigest() != b.get("chain"):
            problems.append("its chain value is wrong")
        rows = [ledger.get(q) for q in range(b.get("from_seq", 0), b.get("to_seq", -1) + 1)]
        if rows and all(rows):
            if merkle_root([leaf_hash(leaf_line(r)) for r in rows]) != b.get("root"):
                problems.append("the ledger no longer matches the sealed root")
        elif any(rows):
            problems.append("part of its ledger is missing")
        if anchors:
            copy = os.path.join(anchors, f"{b.get('n'):010d}.json")
            if not os.path.exists(copy):
                problems.append("no copy in the anchors folder")
            elif json.load(open(copy)).get("body", {}).get("chain") != b.get("chain"):
                problems.append("differs from its copy in S3: history was rewritten")
        print(f"{'OK  ' if not problems else 'FAIL'} seal {b.get('n')}: {b.get('count')} entries, sealed "
              f"{b.get('sealed_at')}" + ("" if not problems else " — " + "; ".join(problems)))
        ok = ok and not problems
        prev_chain, prev_to, prev_n = b.get("chain"), b.get("to_seq"), b.get("n")
    deletes = [r for r in data.get("ledger", []) if r.get("op") == "delete" and r.get("reason") == "unexplained"]
    for r in deletes:
        print(f"FAIL event {r['event_id']} was deleted outside retention and the noise filter")
    return ok and not deletes


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("files", nargs="*")
    p.add_argument("--key", action="append", default=[], help="a trusted signing public key (PEM file)")
    p.add_argument("--chain", help="a seal chain export")
    p.add_argument("--anchors", help="folder with the seal copies from S3")
    a = p.parse_args(argv)
    trusted = [open(k).read() for k in a.key]
    if not a.files and not a.chain:
        p.error("give a document, or --chain")
    ok = True
    for f in a.files:
        ok = verify_document(f, trusted) and ok
    if a.chain:
        ok = verify_chain(a.chain, trusted, a.anchors) and ok
    print("All checks passed." if ok else "Some checks FAILED.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
