# Alert 1770000000000000005 - CORP-DC-02

**TRUE POSITIVE. Confidence: confirmed.** Based on three independent gates, all met.

## Evidence

- Threat intel: VirusTotal detection ratio 38/72 on `9f2c4a1b...`, verdict malicious.
- MDR: "Confirmed malicious, endpoint contained." An analyst verdict on the alert.
- Corroboration: Palo Alto Networks Firewall carries the same destination 203.0.113.77
  outbound from CORP-DC-02, an independent source from the EDR detection.

Two independent sources corroborate and threat intel is positive, which is exactly the
bar for the ladder word "confirmed". Hedging a verdict this well-supported would be as
wrong as over-calling a weak one.

## MITRE ATT&CK

- T1003.001 - OS Credential Dumping: LSASS Memory
- T1071.001 - Application Layer Protocol: Web Protocols (the 203.0.113.77 channel)

## Impact

CORP-DC-02 is a domain controller, so credential material for the domain must be treated
as exposed. The endpoint is already contained by MDR; the outstanding work is a krbtgt
double-reset and privileged-account credential rotation.

## Query appendix

- **Purpose:** find any other endpoint reaching 203.0.113.77.
  **Scope:** Palo Alto Networks Firewall, 7 days, UTC, tenant `<tenant>`.
  **Result:** 1 row (CORP-DC-02 only).
  **Evidence:** `2026-09-05T23:41:10Z | allow | 10.20.0.12 | 203.0.113.77 | 443`
