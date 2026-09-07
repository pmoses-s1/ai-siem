# MEDIUM investigation - alerts 1770000000000000003 / 1770000000000000004

**Suspicious, single-source.** Two endpoints, three queries, one of them empty.

## Findings

CORP-WKS-0101 shows an encoded PowerShell invocation spawned by a browser process,
followed 90 seconds later by a DNS resolution to a domain first seen this week.
CORP-WKS-0207 shows nothing comparable: the registry-persistence check returned no rows.

## MITRE ATT&CK

- T1059.001 - Command and Scripting Interpreter: PowerShell (CORP-WKS-0101)
- T1547.001 - Registry Run Keys / Startup Folder: **no evidence of**, query returned 0 rows

## Query appendix

Every PowerQuery executed during this investigation, in execution order.

### 1. Process tree, CORP-WKS-0101

- **Purpose:** reconstruct the process lineage around the alert time.
- **Query:**

```text
event.type = 'Process Creation' endpoint.name = 'CORP-WKS-0101'
| columns event.time, src.process.pid, src.process.cmdline, src.process.user, src.process.parent.cmdline
| sort -event.time
| limit 100
```

- **Scope:** SentinelOne EDR, 2026-09-06T08:00:00Z to 2026-09-06T12:00:00Z, tenant `<tenant>`.
- **Result:** 47 rows.
- **Evidence:**

```text
2026-09-06T09:14:22Z | 7412 | powershell.exe -enc SQBFAFgA... | CORP\a.rivera | "chrome.exe" --type=renderer
2026-09-06T09:14:23Z | 7480 | cmd.exe /c whoami /groups   | CORP\a.rivera | powershell.exe -enc SQBFAFgA...
```

### 2. Network behaviour, CORP-WKS-0101

- **Purpose:** find outbound activity from the same process chain.
- **Query:**

```text
endpoint.name = 'CORP-WKS-0101' event.type in ('DNS Resolved', 'IP Connect')
| columns event.time, event.type, src.process.cmdline, event.dns.request, dst.ip.address, dst.port.number
| sort -event.time
| limit 100
```

- **Scope:** SentinelOne EDR, 2026-09-06T08:00:00Z to 2026-09-06T12:00:00Z, tenant `<tenant>`.
- **Result:** 12 rows.
- **Evidence:**

```text
2026-09-06T09:15:52Z | DNS Resolved | powershell.exe -enc SQBFAFgA... | cdn-update-svc.example | 203.0.113.77 | 443
```

### 3. Registry persistence, CORP-WKS-0207

- **Purpose:** check whether the second endpoint carries Run-key persistence.
- **Query:**

```text
endpoint.name = 'CORP-WKS-0207' event.type = 'Registry Value Create'
| filter registry.keyPath contains:anycase("\\CurrentVersion\\Run")
| columns event.time, registry.keyPath, registry.value, src.process.cmdline
| sort -event.time
| limit 100
```

- **Scope:** SentinelOne EDR, 2026-09-06T08:00:00Z to 2026-09-06T12:00:00Z, tenant `<tenant>`.
- **Result:** **0 rows / empty.**
- **Evidence:** none returned. Recorded as a finding: there is no evidence of Run-key
  persistence on CORP-WKS-0207 in this window, which is what rules T1547.001 out for
  that host rather than leaving it unexamined.
