# [Zabbix 7.4.16 / 7.0.32] Incorrect authorization: DENY host-group rights ignored when recalculating ugset permissions after usergroup.update (DEV-5196 patch-gap)

**Program:** Zabbix (HackerOne) — public, paid  
**Asset:** Zabbix monitoring solution / Frontend API (supported releases)  
**Version / commit / digest:**
- Vulnerable tags: `7.4.16`, `7.0.32`
- Official tarball `zabbix-7.4.16.tar.gz` sha256 `0e2c391dc184acce8e34250e7326a51e19c8bcee31e67b8497f5526247ecd261`
- Sink: `ui/include/classes/api/services/CUserGroup.php` sha256 `5a96a3650c948d0fa99849238f23a3c11c1766f91641b37f9c8aeb0aa6c981da`
- Unreleased fix: DEV-5196 — `release/7.4` `2f2d7fb70036991ab21045b2fd43e5cd99713bc3` (2026-10-27); `release/7.0` `fbe2904def15b62e59e73e310280e9d979a5326a`

## Summary
When a Super Admin updates host/template group rights on one user group, Zabbix recalculates the effective `permission` rows for every user-group-set (ugset) that contains that user group. On 7.4.16 / 7.0.32 the recalculation only considers the **changed** user group's new rights. An **unchanged** sibling user group that still has **PERM_DENY** on the same host group is not folded into the new effective value. The `permission` table is then written with READ or READ_WRITE, wiping DENY.

This breaks the documented invariant that Deny always overrides Read / Read-write across a user's groups.

## Root cause + locations
Fingerprint: `Zabbix | CUserGroup::updateRights | usergroup.update (hostgroup_rights) | permission map write via getUgSetPermissions/getPermissions | new effective ignores unchanged groups' DENY | CWE-863 | cross-group DENY bypass → host access elevation | Super Admin triggers; victim is any user in overlapping ugset`

Vulnerable (7.4.16) — `getUgSetPermissions` only walks `changed_permissions`; `getPermissions` then uses aggregated `['new']` from changed groups only; `updatePermissions` INSERTs when new≥READ and db_effective < READ (including DENY-by-absence).

Fixed (DEV-5196) — `prepareUgSetPermissions` folds **all** current rights of every user group in the ugset into the prospective new effective (including DENY), then skips the write when new == db.

## Prerequisites
1. At least one user who is a member of **two** user groups G_deny and G_other (same ugset).
2. G_deny has **Deny** on host group HG; G_other has no rights (or weaker) on HG.
3. Effective access for that user to hosts in HG is Deny (correct).
4. Caller is Super Admin with `usergroup.update`.

## Reproduction steps (synthetic / local)
1. Build ugset S = {G_deny, G_other}; hostgroup HG in hgset H; rights G_deny→DENY(HG); permission map conceptually DENY for (S,H).
2. Call the pre-fix recalc with change: G_other NONE→READ on HG (rights table not yet updated — same order as production `updateRights`).
3. Observe pre-fix path writes effective READ; fixed path keeps DENY.

Offline harness (no Zabbix daemon, no customer data):
```bash
php harness_deny_bypass.php
# EXPECTED: DENY
# PRE-FIX (7.4.16): READ VULNERABLE (DENY wiped)
# FIXED (DEV-5196): DENY OK
php harness_negatives.php
# NC1/NC4 PASS; VULN READ/RW PASS
```

## Actual vs expected
| Path | Effective (S,H) after G_other += READ |
|------|----------------------------------------|
| Expected (docs: DENY wins) | DENY |
| 7.4.16 / 7.0.32 | **READ** (or READ_WRITE if sibling granted RW) |
| DEV-5196 fixed | DENY (no permission-row write) |

## Negative controls
- NC1: single user group, NONE→READ → both paths grant READ (PASS).
- NC4: sibling both READ, one upgraded to RW → both paths grant RW (PASS).
- Fixed path on vuln scenarios preserves DENY (PASS).

## Impact + limitations
- **Impact:** Users retain or gain Read/Read-write on host (and template) groups that another of their groups explicitly Denies. Enables monitoring data / macro / configuration disclosure and, with RW, host configuration changes on previously denied hosts.
- **Trigger privilege:** `usergroup.update` requires `USER_TYPE_SUPER_ADMIN`. Same `CUserGroup::updateForce` is also called from `CHostGroup` / `CTemplateGroup` when rewriting attached rights (still privileged).
- **Not:** unauthenticated; not a Super Admin self-priv-esc (Super Admin already bypasses DENY per product design). The victims are **non-admin users** whose Deny was supposed to stick.
- Per Zabbix H1 reward table, “Exploitation requires administrator privileges” → **Medium (~$500)**. Conservative CVSS 3.1: `AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:L/A:N` ≈ **5.5 Medium** (Confidentiality High if macros/credentials on denied hosts; Integrity Low for RW case).

## CWE
CWE-863 Incorrect Authorization

## Duplicate search (2026-11-02)
- No CVE/GHSA/advisory referencing DEV-5196 or “effective permission when updating user group rights”.
- CVE-2024-36467 is a **different** usergroup issue (`user.update` self-add to groups) — not this sink.
- Commit message public on GitHub/git.zabbix.com but **unreleased** to 7.4.16 / 7.0.32; no security advisory filed.
- Distinct from C30 (trapper DEV-5052) and C49 (usermacro.get missing ugsetid / DEV-4859).

## Distinctness
New sink (`CUserGroup` permission-map recalc / DENY fold), new ticket (DEV-5196), not a restate of C49's SQL filter bug.

## Remediation
Ship DEV-5196 to 7.4.x / 7.0.x stable (already on release branches). Until then, avoid overlapping user-group memberships where one group uses Deny as a hard block against another group's grants, or avoid editing the non-Deny group's rights until patched.

## Realistic payout
Zabbix H1 Medium guideline **$500** (admin-triggered authz / limited impact band). Possible upward if triage treats broken DENY as High for multi-tenant deployments; report conservatively as Medium.

## Evidence package
See `EVIDENCE_C56.tar.gz` (harnesses, outputs, vulnerable/fixed slices, version pins). Integrity hash recorded in `/workspace/bounty-research/hashes.sha256`.

---
**Submission status:** NOT SUBMITTED. Held pending user approval / H1 KYC (same queue as C45/C49).
