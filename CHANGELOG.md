# Changelog

## 1.0.3 (2026-11-12)

- Block mode: when the console's name is an alias (for example of an AWS load balancer), the target name is
  allowed from the start. The runner's resolver remembers the alias after the sensor's first lookup and then asks
  for the target directly, which 1.0.2 refused (harmless, but it showed as blocked).

## 1.0.2 (2026-11-12)

- Block mode: the console's addresses are opened before the sensor fetches the threat-intel list at start.
  Before, the fetch ran before the DNS proxy was up, was refused, and the sensor fell back to public feeds.

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
