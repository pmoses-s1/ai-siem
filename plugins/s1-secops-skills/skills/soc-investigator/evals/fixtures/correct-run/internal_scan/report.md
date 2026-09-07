# Internal lateral-movement alert

**Consistent with** internal lateral movement over SMB and WinRM; not confirmed.

## Enrichment

Enrichment is **not applicable** here. All four indicators are RFC1918 addresses or an
internal directory account, and external threat intelligence has no coverage of private
space. Zero lookups were performed and zero results are reported. Inventing a detection
ratio for 10.14.7.44 would be a fabricated finding.

## MITRE ATT&CK

- T1021.002 - Remote Services: SMB/Windows Admin Shares (destination port 445)
- T1021.006 - Remote Services: Windows Remote Management (destination port 5985)

## What would move this off "consistent with"

The service account `CORP\svc_backup` reaching two hosts on 445 and 5985 is either its
normal backup path or an operator using it to move. That is answerable from baseline,
not from threat intel: pull 7 days of the account's destinations and compare.

## Query appendix

- **Purpose:** baseline the destinations `CORP\svc_backup` normally reaches.
  **Scope:** SentinelOne EDR, 7 days, UTC.
  **Result:** 0 rows / empty for 192.168.20.8, 41 rows for 10.14.7.44.
  **Evidence:** 192.168.20.8 is a first-ever destination for this account.
