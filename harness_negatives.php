<?php
define('PERM_READ_WRITE', 3);
define('PERM_READ', 2);
define('PERM_DENY', 0);
define('PERM_NONE', -1);
require __DIR__.'/harness_lib.php';

function run_case($name, $RIGHTS, $changed_pre, $changed_fix, $UGSET_GROUP, $HGSET_GROUP, $init_perm, $expected) {
    echo "--- $name ---\n";
    // PRE
    $ug = pre_getUgSetPermissions($changed_pre, $UGSET_GROUP);
    $db = pre_getDbUgSetPermissions($ug, $UGSET_GROUP, $RIGHTS);
    pre_unsetUnhanged($ug, $db);
    if ($ug) {
        [$p,$d] = pre_getPermissions($ug, $db, $HGSET_GROUP);
        $pre = apply_update($p, $d, $init_perm);
    } else { $pre = $init_perm; }
    // FIX
    $ugf = fixed_getChangedUgSetPermissions($changed_fix, $UGSET_GROUP);
    [$ugf2,$dbf] = fixed_prepareUgSetPermissions($ugf, $changed_fix, $UGSET_GROUP, $RIGHTS);
    if ($ugf2) {
        [$p,$d] = fixed_getPermissions($ugf2, $dbf, $HGSET_GROUP);
        $fix = apply_update($p, $d, $init_perm);
    } else { $fix = $init_perm; }
    $pr = $pre['S']['H'] ?? PERM_NONE;
    $fr = $fix['S']['H'] ?? PERM_NONE;
    echo "  PRE=".perm_name($pr)." FIX=".perm_name($fr)." EXPECTED=".perm_name($expected)."\n";
    return ['pre'=>$pr,'fix'=>$fr,'exp'=>$expected];
}

$UG = ['G_deny'=>['S'],'G_other'=>['S']];
$HG = ['H'=>['HG']];
$init = ['S'=>['H'=>PERM_DENY]]; // conceptual; table may omit DENY rows

$results = [];

// NC1: single group, no DENY overlap — READ grant should stick (both paths)
$results[] = run_case('NC1 single-group READ grant',
    ['G_only'=>[]],
    ['G_only'=>['HG'=>['new'=>PERM_READ,'old'=>PERM_NONE]]],
    ['G_only'=>['HG'=>PERM_READ]],
    ['G_only'=>['S']], $HG, ['S'=>[]], PERM_READ);

// NC2: DENY wipe (vulnerable case)
$results[] = run_case('VULN DENY wiped by sibling READ',
    ['G_deny'=>['HG'=>PERM_DENY],'G_other'=>[]],
    ['G_other'=>['HG'=>['new'=>PERM_READ,'old'=>PERM_NONE]]],
    ['G_other'=>['HG'=>PERM_READ]],
    $UG, $HG, $init, PERM_DENY);

// NC3: DENY wiped by sibling RW
$results[] = run_case('VULN DENY wiped by sibling RW',
    ['G_deny'=>['HG'=>PERM_DENY],'G_other'=>[]],
    ['G_other'=>['HG'=>['new'=>PERM_READ_WRITE,'old'=>PERM_NONE]]],
    ['G_other'=>['HG'=>PERM_READ_WRITE]],
    $UG, $HG, $init, PERM_DENY);

// NC4: both groups READ, upgrade one — should become RW on both after fix/pre
$results[] = run_case('NC4 upgrade READ->RW with sibling READ (expect RW)',
    ['G_a'=>['HG'=>PERM_READ],'G_b'=>['HG'=>PERM_READ]],
    ['G_a'=>['HG'=>['new'=>PERM_READ_WRITE,'old'=>PERM_READ]]],
    ['G_a'=>['HG'=>PERM_READ_WRITE]],
    ['G_a'=>['S'],'G_b'=>['S']], $HG, ['S'=>['H'=>PERM_READ]], PERM_READ_WRITE);

$fail = 0;
foreach ($results as $i => $r) {
    // For VULN cases, PRE should differ from expected; FIX should match
    // For NC cases, both should match expected
}
echo "\nSummary checks:\n";
// NC1
echo "NC1 PRE==FIX==READ: ".(($results[0]['pre']===PERM_READ && $results[0]['fix']===PERM_READ)?'PASS':'FAIL')."\n";
echo "VULN READ: PRE!=DENY && FIX==DENY: ".(($results[1]['pre']!==PERM_DENY && $results[1]['fix']===PERM_DENY)?'PASS':'FAIL')."\n";
echo "VULN RW:   PRE!=DENY && FIX==DENY: ".(($results[2]['pre']!==PERM_DENY && $results[2]['fix']===PERM_DENY)?'PASS':'FAIL')."\n";
echo "NC4 PRE==FIX==RW: ".(($results[3]['pre']===PERM_READ_WRITE && $results[3]['fix']===PERM_READ_WRITE)?'PASS':'FAIL')."\n";
