<?php
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

