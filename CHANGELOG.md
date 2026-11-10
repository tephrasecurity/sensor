# Changelog

## 1.0.0

First public release.

- Records DNS lookups, outbound connections (with the process that opened them), programs executed and source
  files changed, mapped to the job.
- Audit and block egress modes, with an allowlist suggested from audit runs in the step summary.
- Threat intel: refuses known-bad domains and IPs in either mode (Tephra Trace's list, or abuse.ch Feodo Tracker
  and Spamhaus DROP).
- Lists the actions the runner downloaded for the job, nested ones included.
- Optional live streaming to Tephra Trace; reports brokered-credential leases by hash only.
