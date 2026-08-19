# Incident Report: Privilege Escalation Detected

**Alert:** `Privilege Escalation Detected`
**Severity:** Critical
**Affected Account:** `john.doe`
**Status:** Contained

## Summary
The `Privilege Escalation Detected` correlation search fired when Event ID 4672
(Special Privileges Assigned) was logged for `john.doe`, an account whose
`user_privilege_lookup` entry marks it as **Standard** — indicating unauthorized
elevation to administrative rights.

## Timeline

| Time | Event | Host |
|---|---|---|
| 10:06:10 | Successful login (4624) | DC-01 |
| 10:06:22 | Special privileges assigned (4672) | DC-01 |
| 10:07:05 | New local admin group membership change (4732) | DC-01 |

## Root Cause
Following lateral movement to `DC-01` (see `lateral_movement_incident.md`), the
attacker leveraged cached credentials or a token impersonation technique to have
`john.doe` assigned SeDebugPrivilege / SeImpersonatePrivilege, then added the
account to the local Administrators group.

## Response Actions
1. Removed `john.doe` from the Administrators group.
2. Forced password reset and revoked active Kerberos tickets for the account.
3. Reviewed `DC-01` Security event log for further 4732/4728 group membership changes.
4. Escalated to full incident response — treated `DC-01` as compromised pending
   forensic review.

## Detection Gaps / Follow-ups
- Add alerting on 4732/4728 (group membership changes) for privileged groups,
  correlated with recent 4672 events on the same host.
- Tighten `user_privilege_lookup` maintenance process so privilege-level changes
  are reviewed and approved before being reflected in Splunk.
