<?php
/**
 * Round 18 — DEV-5196 patch-gap harness
 * Reimplements the EXACT aggregation + unsetUnhanged + getPermissions
 * logic from Zabbix 7.4.16 CUserGroup.php (pre-fix) vs fixed prepareUgSetPermissions.
 *
 * Scenario (DENY wipe / CWE-863):
 *   User U ∈ UserGroup G_deny AND G_other  → ugset S={G_deny, G_other}
 *   Hostgroup HG ∈ hgset H
 *   G_deny has PERM_DENY on HG; G_other has PERM_NONE
 *   Effective permission table row (S,H) = DENY (correct)
 *   Admin updates G_other: adds PERM_READ on HG (normal usergroup.update)
 *   EXPECTED: effective stays DENY (DENY wins across groups in ugset)
 *   ACTUAL (7.4.16): permission table updated to READ — DENY bypassed
 *
 * Constants match ui/include/defines.inc.php @ 7.4.16
 */
define('PERM_READ_WRITE', 3);
define('PERM_READ', 2);
define('PERM_DENY', 0);
define('PERM_NONE', -1);

// ---- Mock DB state ----
$UGSET_GROUP = [
    // usrgrpid => [ugsetids...]
    'G_deny'  => ['S'],
    'G_other' => ['S'],
];
$RIGHTS = [
    // usrgrpid => [ hostgroupid => permission ]
    'G_deny'  => ['HG' => PERM_DENY],
    'G_other' => [],  // none yet; will be "added" as the change
];
$HGSET_GROUP = [
    // hgsetid => [hostgroup ids]
    'H' => ['HG'],
];
// Current effective permission table (what access checks use):
$PERMISSION = [
    // ugsetid => [ hgsetid => permission ]
    'S' => ['H' => PERM_DENY],
];

// ---- Pre-fix helpers (verbatim logic from 7.4.16) ----

function pre_getUgSetPermissions(array $changed_permissions, array $UGSET_GROUP): array {
    $ugset_permissions = [];
    foreach ($changed_permissions as $usrgrpid => $groups) {
        if (!isset($UGSET_GROUP[$usrgrpid])) continue;
        foreach ($UGSET_GROUP[$usrgrpid] as $ugsetid) {
            foreach ($groups as $groupid => $permission) {
                if (!isset($ugset_permissions[$ugsetid][$groupid])) {
                    $ugset_permissions[$ugsetid][$groupid]['new'] = $permission['new'];
                    $ugset_permissions[$ugsetid][$groupid]['old'] = $permission['old'];
                    $ugset_permissions[$ugsetid][$groupid]['usrgrp_count'] = 1;
                } else {
                    if ($ugset_permissions[$ugsetid][$groupid]['new'] != PERM_DENY
                            && ($permission['new'] > $ugset_permissions[$ugsetid][$groupid]['new']
                                || $permission['new'] == PERM_DENY)) {
                        $ugset_permissions[$ugsetid][$groupid]['new'] = $permission['new'];
                    }
                    if ($permission['old'] == $ugset_permissions[$ugsetid][$groupid]['old']) {
                        $ugset_permissions[$ugsetid][$groupid]['usrgrp_count']++;
                    } elseif ($ugset_permissions[$ugsetid][$groupid]['old'] != PERM_DENY
                            && ($permission['old'] > $ugset_permissions[$ugsetid][$groupid]['old']
                                || $permission['old'] == PERM_DENY)) {
                        $ugset_permissions[$ugsetid][$groupid]['old'] = $permission['old'];
                        $ugset_permissions[$ugsetid][$groupid]['usrgrp_count'] = 1;
                    }
                }
            }
        }
    }
    return $ugset_permissions;
}

function pre_getDbUgSetPermissions(array $ugset_permissions, array $UGSET_GROUP, array $RIGHTS): array {
    $db_ugset_permissions = array_fill_keys(array_keys($ugset_permissions), []);
    // Simulate: SELECT ugg.ugsetid,ugg.usrgrpid,r.id,r.permission FROM ugset_group ugg JOIN rights r ...
    foreach ($UGSET_GROUP as $usrgrpid => $ugsetids) {
        foreach ($ugsetids as $ugsetid) {
            if (!array_key_exists($ugsetid, $db_ugset_permissions)) continue;
            if (!isset($RIGHTS[$usrgrpid])) continue;
            foreach ($RIGHTS[$usrgrpid] as $id => $permission) {
                if (!array_key_exists($id, $db_ugset_permissions[$ugsetid])) {
                    $db_ugset_permissions[$ugsetid][$id]['old'] = $permission;
                    $db_ugset_permissions[$ugsetid][$id]['usrgrp_count'] = 1;
                } else {
                    if ($permission == $db_ugset_permissions[$ugsetid][$id]['old']) {
                        $db_ugset_permissions[$ugsetid][$id]['usrgrp_count']++;
                    } elseif ($db_ugset_permissions[$ugsetid][$id]['old'] != PERM_DENY
                            && ($permission > $db_ugset_permissions[$ugsetid][$id]['old']
                                || $permission == PERM_DENY)) {
                        $db_ugset_permissions[$ugsetid][$id]['old'] = $permission;
                        $db_ugset_permissions[$ugsetid][$id]['usrgrp_count'] = 1;
                    }
                }
            }
        }
    }
    return $db_ugset_permissions;
}

function pre_unsetUnhanged(array &$ugset_permissions, array &$db_ugset_permissions): void {
    foreach ($ugset_permissions as $ugsetid => $group_permissions) {
        foreach ($group_permissions as $groupid => $permission) {
            $changed = false;
            if (!array_key_exists($groupid, $db_ugset_permissions[$ugsetid])) {
                $changed = true;
            } else {
                $db_permission = $db_ugset_permissions[$ugsetid][$groupid];
                if ($permission['new'] > $db_permission['old']
                        || ($permission['new'] == PERM_DENY && $db_permission['old'] != PERM_DENY)
                        || ($permission['old'] == $db_permission['old']
                            && $permission['usrgrp_count'] == $db_permission['usrgrp_count'])) {
                    $changed = true;
                }
            }
            if (!$changed) {
                unset($ugset_permissions[$ugsetid][$groupid]);
            }
        }
        if (!$ugset_permissions[$ugsetid]) {
            unset($ugset_permissions[$ugsetid], $db_ugset_permissions[$ugsetid]);
        }
    }
}

function pre_getPermissions(array $ugset_permissions, array $db_ugset_permissions, array $HGSET_GROUP): array {
    $permissions = [];
    $db_permissions = [];
    $groupids = [];
    $group_ugsetids = [];
    foreach ($ugset_permissions as $ugsetid => $group_permissions) {
        $groupids += $group_permissions;
        foreach ($group_permissions as $groupid => $foo) {
            $group_ugsetids[$groupid][$ugsetid] = true;
        }
        foreach ($db_ugset_permissions[$ugsetid] as $groupid => $foo) {
            $group_ugsetids[$groupid][$ugsetid] = true;
        }
    }
    // Simulate hgset_group join
    foreach ($HGSET_GROUP as $hgsetid => $hgs) {
        // only hgsets that contain at least one of groupids
        $hit = false;
        foreach ($hgs as $g) { if (isset($groupids[$g])) { $hit = true; break; } }
        if (!$hit) continue;
        foreach ($hgs as $groupid) {
            if (!isset($group_ugsetids[$groupid])) continue;
            foreach ($group_ugsetids[$groupid] as $ugsetid => $foo) {
                if (!array_key_exists($groupid, $ugset_permissions[$ugsetid])
                        && !array_key_exists($groupid, $db_ugset_permissions[$ugsetid])) {
                    continue;
                }
                $permission = array_key_exists($groupid, $ugset_permissions[$ugsetid])
                    ? $ugset_permissions[$ugsetid][$groupid]['new']
                    : $db_ugset_permissions[$ugsetid][$groupid]['old'];
                if (!isset($permissions[$ugsetid][$hgsetid])
                        || ($permissions[$ugsetid][$hgsetid] != PERM_DENY
                            && ($permission > $permissions[$ugsetid][$hgsetid] || $permission == PERM_DENY))) {
                    $permissions[$ugsetid][$hgsetid] = $permission;
                }
                $db_permission = array_key_exists($groupid, $db_ugset_permissions[$ugsetid])
                    ? $db_ugset_permissions[$ugsetid][$groupid]['old']
                    : PERM_NONE;
                if (!isset($db_permissions[$ugsetid][$hgsetid])
                        || ($db_permissions[$ugsetid][$hgsetid] != PERM_DENY
                            && ($db_permission > $db_permissions[$ugsetid][$hgsetid]
                                || $db_permission == PERM_DENY))) {
                    $db_permissions[$ugsetid][$hgsetid] = $db_permission;
                }
            }
        }
    }
    return [$permissions, $db_permissions];
}

function apply_update(array $permissions, array $db_permissions, array $PERMISSION): array {
    // Mirrors updatePermissions write decisions
    $out = $PERMISSION;
    foreach ($permissions as $ugsetid => $hgset_permissions) {
        foreach ($hgset_permissions as $hgsetid => $permission) {
            $db_permission = $db_permissions[$ugsetid][$hgsetid];
            if ($permission >= PERM_READ) {
                if ($db_permission >= PERM_READ) {
                    if ($permission != $db_permission) {
                        $out[$ugsetid][$hgsetid] = $permission;
                    }
                } else {
                    // insert (also covers overwriting when db was DENY/NONE stored oddly)
                    $out[$ugsetid][$hgsetid] = $permission;
                }
            } elseif ($db_permission >= PERM_READ) {
                unset($out[$ugsetid][$hgsetid]);
            }
            // NOTE: if permission==DENY and db was DENY, no change; if permission>=READ and db was DENY (< READ), INSERT READ
        }
    }
    return $out;
}

// ---- Fixed helpers (DEV-5196 / prepareUgSetPermissions fold) ----

function fixed_getChangedUgSetPermissions(array $changed_permissions, array $UGSET_GROUP): array {
    $ugset_permissions = [];
    foreach ($changed_permissions as $usrgrpid => $groups) {
        if (!isset($UGSET_GROUP[$usrgrpid])) continue;
        foreach ($UGSET_GROUP[$usrgrpid] as $ugsetid) {
            foreach ($groups as $groupid => $permission) {
                if (!isset($ugset_permissions[$ugsetid][$groupid])) {
                    $ugset_permissions[$ugsetid][$groupid] = $permission;
                } elseif ($ugset_permissions[$ugsetid][$groupid] != PERM_DENY
                        && ($permission > $ugset_permissions[$ugsetid][$groupid] || $permission == PERM_DENY)) {
                    $ugset_permissions[$ugsetid][$groupid] = $permission;
                }
            }
        }
    }
    return $ugset_permissions;
}

function fixed_prepareUgSetPermissions(array $ugset_permissions, array $changed_permissions, array $UGSET_GROUP, array $RIGHTS): array {
    $db_ugset_permissions = array_fill_keys(array_keys($ugset_permissions), []);
    foreach ($UGSET_GROUP as $usrgrpid => $ugsetids) {
        foreach ($ugsetids as $ugsetid) {
            if (!array_key_exists($ugsetid, $db_ugset_permissions)) continue;
            if (!isset($RIGHTS[$usrgrpid])) continue;
            foreach ($RIGHTS[$usrgrpid] as $id => $permission) {
                if (!array_key_exists($id, $db_ugset_permissions[$ugsetid])) {
                    $db_ugset_permissions[$ugsetid][$id] = $permission;
                } elseif ($db_ugset_permissions[$ugsetid][$id] != PERM_DENY
                        && ($permission > $db_ugset_permissions[$ugsetid][$id] || $permission == PERM_DENY)) {
                    $db_ugset_permissions[$ugsetid][$id] = $permission;
                }
                // Fold unchanged groups into NEW side (the core fix):
                if (!array_key_exists($id, $ugset_permissions[$ugsetid])
                        || (array_key_exists($usrgrpid, $changed_permissions)
                            && array_key_exists($id, $changed_permissions[$usrgrpid]))) {
                    continue;
                }
                if ($ugset_permissions[$ugsetid][$id] != PERM_DENY
                        && ($permission > $ugset_permissions[$ugsetid][$id] || $permission == PERM_DENY)) {
                    $ugset_permissions[$ugsetid][$id] = $permission;
                }
            }
        }
    }
    foreach ($ugset_permissions as $ugsetid => $group_permissions) {
        foreach ($group_permissions as $groupid => $permission) {
            $db_permission = array_key_exists($groupid, $db_ugset_permissions[$ugsetid])
                ? $db_ugset_permissions[$ugsetid][$groupid]
                : PERM_NONE;
            if ($permission == $db_permission) {
                unset($ugset_permissions[$ugsetid][$groupid]);
            }
        }
        if (!$ugset_permissions[$ugsetid]) {
            unset($ugset_permissions[$ugsetid], $db_ugset_permissions[$ugsetid]);
        }
    }
    return [$ugset_permissions, $db_ugset_permissions];
}

function fixed_getPermissions(array $ugset_permissions, array $db_ugset_permissions, array $HGSET_GROUP): array {
    // Same as pre but scalar perms instead of ['new']/['old']
    $permissions = [];
    $db_permissions = [];
    $groupids = [];
    $group_ugsetids = [];
    foreach ($ugset_permissions as $ugsetid => $group_permissions) {
        $groupids += $group_permissions;
        foreach ($group_permissions as $groupid => $foo) {
            $group_ugsetids[$groupid][$ugsetid] = true;
        }
        foreach ($db_ugset_permissions[$ugsetid] as $groupid => $foo) {
            $group_ugsetids[$groupid][$ugsetid] = true;
        }
    }
    foreach ($HGSET_GROUP as $hgsetid => $hgs) {
        $hit = false;
        foreach ($hgs as $g) { if (isset($groupids[$g])) { $hit = true; break; } }
        if (!$hit) continue;
        foreach ($hgs as $groupid) {
            if (!isset($group_ugsetids[$groupid])) continue;
            foreach ($group_ugsetids[$groupid] as $ugsetid => $foo) {
                if (!array_key_exists($groupid, $ugset_permissions[$ugsetid])
                        && !array_key_exists($groupid, $db_ugset_permissions[$ugsetid])) {
                    continue;
                }
                $permission = array_key_exists($groupid, $ugset_permissions[$ugsetid])
                    ? $ugset_permissions[$ugsetid][$groupid]
                    : $db_ugset_permissions[$ugsetid][$groupid];
                if (!isset($permissions[$ugsetid][$hgsetid])
                        || ($permissions[$ugsetid][$hgsetid] != PERM_DENY
                            && ($permission > $permissions[$ugsetid][$hgsetid] || $permission == PERM_DENY))) {
                    $permissions[$ugsetid][$hgsetid] = $permission;
                }
                $db_permission = array_key_exists($groupid, $db_ugset_permissions[$ugsetid])
                    ? $db_ugset_permissions[$ugsetid][$groupid]
                    : PERM_NONE;
                if (!isset($db_permissions[$ugsetid][$hgsetid])
                        || ($db_permissions[$ugsetid][$hgsetid] != PERM_DENY
                            && ($db_permission > $db_permissions[$ugsetid][$hgsetid]
                                || $db_permission == PERM_DENY))) {
                    $db_permissions[$ugsetid][$hgsetid] = $db_permission;
                }
            }
        }
    }
    return [$permissions, $db_permissions];
}

function perm_name($p) {
    return match ($p) {
        3 => 'READ_WRITE',
        2 => 'READ',
        0 => 'DENY',
        -1 => 'NONE',
        default => (string)$p,
    };
}

echo "=== DEV-5196 DENY-bypass harness ===\n";
echo "Initial permission[S][H] = " . perm_name($PERMISSION['S']['H']) . "\n";
echo "Rights: G_deny=DENY(HG), G_other=NONE\n";
echo "Change: usergroup.update G_other hostgroup_rights += READ(HG)\n\n";

// Change as recorded by pre-fix updateRights (rights table NOT yet written):
$changed_permissions = [
    'G_other' => [
        'HG' => ['new' => PERM_READ, 'old' => PERM_NONE],
    ],
];

// ---- Run PRE-FIX (7.4.16) ----
$ug = pre_getUgSetPermissions($changed_permissions, $UGSET_GROUP);
$db = pre_getDbUgSetPermissions($ug, $UGSET_GROUP, $RIGHTS);
echo "[PRE] ugset_permissions after getUgSetPermissions:\n";
print_r($ug);
echo "[PRE] db_ugset_permissions:\n";
print_r($db);
pre_unsetUnhanged($ug, $db);
echo "[PRE] after unsetUnhanged (empty means skipped):\n";
print_r($ug);
if ($ug) {
    [$perms, $dbperms] = pre_getPermissions($ug, $db, $HGSET_GROUP);
    echo "[PRE] getPermissions new=\n"; print_r($perms);
    echo "[PRE] getPermissions db=\n"; print_r($dbperms);
    $PERMISSION_PRE = apply_update($perms, $dbperms, $PERMISSION);
} else {
    $PERMISSION_PRE = $PERMISSION;
}
echo "[PRE] RESULT permission[S][H] = " . perm_name($PERMISSION_PRE['S']['H'] ?? PERM_NONE) . "\n\n";

// ---- Run FIXED (DEV-5196) ----
// Fixed stores scalar in changed_permissions:
$changed_fixed = [
    'G_other' => ['HG' => PERM_READ],
];
$ugf = fixed_getChangedUgSetPermissions($changed_fixed, $UGSET_GROUP);
[$ugf2, $dbf] = fixed_prepareUgSetPermissions($ugf, $changed_fixed, $UGSET_GROUP, $RIGHTS);
echo "[FIX] after prepareUgSetPermissions ugset (empty=no write):\n";
print_r($ugf2);
echo "[FIX] db:\n";
print_r($dbf);
if ($ugf2) {
    [$perms, $dbperms] = fixed_getPermissions($ugf2, $dbf, $HGSET_GROUP);
    $PERMISSION_FIX = apply_update($perms, $dbperms, $PERMISSION);
} else {
    $PERMISSION_FIX = $PERMISSION;
}
echo "[FIX] RESULT permission[S][H] = " . perm_name($PERMISSION_FIX['S']['H'] ?? PERM_NONE) . "\n\n";

// ---- Verdict ----
$pre = $PERMISSION_PRE['S']['H'] ?? PERM_NONE;
$fix = $PERMISSION_FIX['S']['H'] ?? PERM_NONE;
$expected = PERM_DENY;

echo "EXPECTED: " . perm_name($expected) . "\n";
echo "PRE-FIX (7.4.16): " . perm_name($pre) . ($pre === $expected ? " OK" : " VULNERABLE (DENY wiped)") . "\n";
echo "FIXED (DEV-5196): " . perm_name($fix) . ($fix === $expected ? " OK" : " STILL BAD") . "\n";

if ($pre !== $expected && $fix === $expected) {
    echo "\nVERDICT: CONFIRMED DENY-bypass on 7.4.16 path; fixed path preserves DENY.\n";
    exit(0);
}
echo "\nVERDICT: harness did not demonstrate expected differential.\n";
exit(1);
