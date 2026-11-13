# Tephra runner sensor

See what your GitHub Actions jobs actually do on the runner: every DNS lookup, every outbound connection and
the program that made it, every program run, and every source file changed. Optionally, block anything the job
didn't declare. Known-bad hosts are refused even in audit mode.

Free and open source (Apache-2.0). Works on its own; pairs with [Tephra Trace](https://tephrasecurity.com) to follow
each run into AWS, Vault and BeyondTrust.

```yaml
steps:
  - uses: actions/checkout@v4
  - uses: tephrasecurity/sensor@v1        # first, so it sees everything after it
  # ... your steps ...
```

At the end of the job you get a step summary (destinations, programs, blocked attempts, and a ready-made
allowlist) and an artifact, `tephra-sensor-<job>`, with everything recorded.

## What it records

| | How |
|---|---|
| **DNS lookups** | A local DNS proxy logs every name the job resolves. In block mode it refuses names not on the allowlist, which also stops DNS tunnelling |
| **Outbound connections** | The firewall logs each new connection; the sensor ties it to the process that opened it (path and command line, credentials redacted) and to the name it resolved |
| **Programs run** | Linux process events: every program executed during the job |
| **Files changed** | Tracked files in the workspace that the job modified |
| **Actions used** | Every action the runner downloaded for the job, nested ones included (`owner/repo@ref`) |
| **Packages installed** | npm, pip and apt packages the job installed, and which npm packages ran install scripts |

It never records file contents, environment variables or secrets.

## Audit, then block

1. Run in audit mode (the default) for a few runs. The step summary lists the domains the job reached, as an
   allowlist you can paste.
2. Switch to block mode:

```yaml
  - uses: tephrasecurity/sensor@v1
    with:
      egress-policy: block
      allowed-endpoints: |
        *.amazonaws.com
        registry.npmjs.org
        api.example.com
```

GitHub's own endpoints are always allowed. Blocked lookups and connections show up in the step summary and the
artifact.

## Known-bad destinations

With `threat-intel: on` (the default), the sensor refuses known-bad domains and IPs in **both** modes:

- **The list:** abuse.ch Feodo Tracker and Spamhaus DROP, read at job start. When `console-url` is set,
  Tephra Trace's curated list is used instead.
- **Never blocked:** major shared platforms (GitHub, AWS, Azure, Google, Docker Hub, npm, PyPI), whatever a feed
  says.

Set `threat-intel: off` to disable it.

## Inputs

| Input | Default | |
|---|---|---|
| `egress-policy` | `audit` | `audit` records only; `block` refuses anything not in `allowed-endpoints` |
| `allowed-endpoints` | | Domains (`*.example.com`), IPs or CIDRs, one per line |
| `threat-intel` | `on` | Refuse known-bad domains and IPs in either mode |
| `console-url` | | Optional: stream records live to a Tephra Trace console |
| `ingest-token` | | The console's ingest token, from a secret. Not needed when the job has `id-token: write`: the sensor then signs in with the job's own OIDC token |
| `artifact-name` | `tephra-sensor` | Artifact name prefix (`-<job>` is added) |
| `retention-days` | `30` | How long GitHub keeps the artifact |
| `fail-on-error` | `false` | Fail the job if the sensor can't start (otherwise warn and continue) |

## Where your data goes

Nowhere, unless you set `console-url`. Everything stays in your own GitHub run: the step summary and the
artifact. With `console-url`, records go only to the console you name, authenticated with your ingest token. At
job start, the sensor reads the public threat-intel feeds (or your console's list).

## Requirements and limits

- **Runners:** Linux runners with passwordless `sudo`, which all GitHub-hosted Ubuntu runners have. Self-hosted
  Linux works when the runner user has `sudo`. Windows and macOS aren't supported yet; the job runs unmonitored,
  with a warning.
- **Overhead:** about 1 second at start. DNS lookups go through a local proxy, and the sensor is pure Python
  standard library plus `iptables`.
- **Containers:** connections from `docker run` containers are recorded through Docker's `DOCKER-USER` chain,
  but not tied to a process. Block mode applies to the runner itself.
- **Root:** a job step running as root can disable any sensor running on the same machine, this one included. The
  sensor makes tampering visible; it can't prevent it.

## Checking Tephra Trace evidence

`verify/tephra-verify.py` checks evidence from a Tephra Trace console offline, without the console: incident
reports, evidence packs and the hourly seal chain (signatures, the chain, Merkle proofs that each event was sealed,
and the copies kept in S3 under Object Lock). Python 3.9+ with `cryptography`, or OpenSSL 3.

```bash
python3 verify/tephra-verify.py tephra-incident-<id>.json --key tephra-key.pem
python3 verify/tephra-verify.py --chain tephra-seal-chain.json --anchors anchors/ --key tephra-key.pem
```

## Verifying a release

Releases are built by GitHub Actions from the tagged commit, with signed build provenance for `dist/`:

```bash
gh attestation verify dist/main.js --repo tephrasecurity/sensor
```

For maximum safety, pin to a commit SHA: `uses: tephrasecurity/sensor@<sha> # v1.0.0`. See
[SECURITY.md](SECURITY.md) for how to report a vulnerability.

## Building

```bash
npm ci && npm run build      # rebuilds dist/ from src/
python3 -m pytest tests      # sensor unit tests
```

CI fails if `dist/` doesn't match `src/`.

## Licence

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
