# Incident Report: Lateral Movement Detected

**Alert:** `Lateral Movement Detected`
**Severity:** High
**Affected User:** `john.doe`
**Status:** Contained

## Summary
The `Lateral Movement Detected` correlation search fired after `john.doe`'s account
showed a failed logon followed shortly by successful logons on two separate hosts
from the same source IP — consistent with credential reuse / pass-the-hash activity.

## Timeline

| Time | Event | Host | Source IP |
|---|---|---|---|
| 10:05:12 | Failed login (4625) | FILE-SRV-01 | 192.168.1.100 |
| 10:05:45 | Successful login (4624) | FILE-SRV-01 | 192.168.1.100 |
| 10:06:10 | Successful login (4624) | DC-01 | 192.168.1.100 |
| 10:06:22 | Special privileges assigned (4672) | DC-01 | 192.168.1.100 |
| 10:06:40 | Suspicious PowerShell process launched | DC-01 | — |

## Root Cause
Credentials for `john.doe` were compromised via a prior brute-force / password-spray
attempt (see `brute_force_detection.spl`) and reused to authenticate laterally from
`FILE-SRV-01` to the domain controller `DC-01`.

## Response Actions
1. Forced password reset for `john.doe`.
2. Blocked source IP `192.168.1.100` at the perimeter firewall.
3. Isolated `DC-01` from the network for forensic imaging.
4. Reviewed `DC-01` for persistence mechanisms (scheduled tasks, new services, new accounts).
5. Rotated krbtgt account credentials as a precaution against Golden Ticket attacks.

## Detection Gaps / Follow-ups
- Add a correlation rule for 4672 immediately following cross-host 4624 events to
  shorten detection time for privilege abuse post-lateral-movement.
- Consider enabling PowerShell Script Block Logging (Event 4104) for deeper visibility
  into post-exploitation activity.
