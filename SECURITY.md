# Security policy

Please report vulnerabilities privately, either through GitHub's **Report a vulnerability** button (Security tab)
or by email to **security@tephrasecurity.com**. Please don't open a public issue.

We acknowledge reports within 3 working days and aim to ship a fix within 30 days, sooner for anything that
weakens a job's isolation or leaks secrets. We credit reporters who'd like it.

Supported: the latest `v1.x` release.

## How releases are protected

- Every release is built in GitHub Actions from a tagged commit. The `dist/` files carry a signed **build
  provenance attestation**. Check it with `gh attestation verify dist/main.js --repo tephrasecurity/sensor`.
- Release tags (`v1.2.3`) are never moved. Only the major tag (`v1`) moves, and only onto a release commit.
- For the strongest guarantee, pin the action to a full commit SHA, as GitHub recommends:
  `uses: tephrasecurity/sensor@<sha> # v1.0.0`.
