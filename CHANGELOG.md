# Changelog

## 1.0.1 (2026-11-12)

- Block mode: when an allowed name is an alias (CNAME) of another name, as with load balancers and CDNs, the
  target name is allowed too, unless it is known-bad. Before, a resolver that looked the target up on its own got
  it refused, which blocked, for example, a console behind an AWS load balancer.

## 1.0.0

First public release.

- Records DNS lookups, outbound connections (with the process that opened them), programs executed and source
  files changed, mapped to the job.
- Audit and block egress modes, with an allowlist suggested from audit runs in the step summary.
- Threat intel: refuses known-bad domains and IPs in either mode (Tephra Trace's list, or abuse.ch Feodo Tracker
  and Spamhaus DROP).
- Lists the actions the runner downloaded for the job, nested ones included.
- Optional live streaming to Tephra Trace; reports brokered-credential leases by hash only.
