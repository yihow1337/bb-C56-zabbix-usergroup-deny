	private static function updateRights(array &$usrgrps, ?array $db_usrgrps = null): void {
		$ins_rights = [];
		$upd_rights = [];
		$del_rightids = [];
		$changed_permissions = [];

		foreach (['hostgroup_rights', 'templategroup_rights'] as $parameter) {
			foreach ($usrgrps as &$usrgrp) {
				if (!array_key_exists($parameter, $usrgrp)) {
					continue;
				}

				$db_rights = $db_usrgrps !== null
					? array_column($db_usrgrps[$usrgrp['usrgrpid']][$parameter], null, 'id')
					: [];

				foreach ($usrgrp[$parameter] as &$right) {
					if (array_key_exists($right['id'], $db_rights)) {
						$db_right = $db_rights[$right['id']];
						unset($db_rights[$right['id']]);

						$right['rightid'] = $db_right['rightid'];

						$upd_right = DB::getUpdatedValues('rights', $right, $db_right);

						if ($upd_right) {
							$upd_rights[] = [
								'values' => $upd_right,
								'where' => ['rightid' => $db_right['rightid']]
							];
							$changed_permissions[$usrgrp['usrgrpid']][$right['id']]['new'] = $right['permission'];
							$changed_permissions[$usrgrp['usrgrpid']][$right['id']]['old'] = $db_right['permission'];
						}
					}
					else {
						$ins_rights[] = [
							'groupid' => $usrgrp['usrgrpid'],
							'id' => $right['id'],
							'permission' => $right['permission']
						];

						if ($db_usrgrps !== null) {
							$changed_permissions[$usrgrp['usrgrpid']][$right['id']]['new'] = $right['permission'];
							$changed_permissions[$usrgrp['usrgrpid']][$right['id']]['old'] = PERM_NONE;
						}
					}
				}
				unset($right);

				foreach ($db_rights as $db_right) {
					$del_rightids[] = $db_right['rightid'];
					$changed_permissions[$usrgrp['usrgrpid']][$db_right['id']]['new'] = PERM_NONE;
					$changed_permissions[$usrgrp['usrgrpid']][$db_right['id']]['old'] = $db_right['permission'];
				}
			}
			unset($usrgrp);
		}

		if ($changed_permissions) {
			$ugset_permissions = self::getUgSetPermissions($changed_permissions);

			if ($ugset_permissions) {
				$db_ugset_permissions = self::getDbUgSetPermissions($ugset_permissions);

				self::updatePermissions($ugset_permissions, $db_ugset_permissions);
			}
		}

		if ($ins_rights) {
			$rightids = DB::insertBatch('rights', $ins_rights);
		}

		if ($upd_rights) {
			DB::update('rights', $upd_rights);
		}

		if ($del_rightids) {
			DB::delete('rights', ['rightid' => $del_rightids]);
		}

		foreach (['hostgroup_rights', 'templategroup_rights'] as $parameter) {
			foreach ($usrgrps as &$usrgrp) {
				if (!array_key_exists($parameter, $usrgrp)) {
					continue;
				}

				foreach ($usrgrp[$parameter] as &$right) {
					if (!array_key_exists('rightid', $right)) {
						$right['rightid'] = array_shift($rightids);
					}
				}
				unset($right);
			}
			unset($usrgrp);
		}
	}

	private static function getUgSetPermissions(array $changed_permissions): array {
		$ugset_permissions = [];

		$options = [
			'output' => ['usrgrpid', 'ugsetid'],
			'filter' => [
				'usrgrpid' => array_keys($changed_permissions)
			]
		];
		$result = DBselect(DB::makeSql('ugset_group', $options));

		while ($row = DBfetch($result)) {
			foreach ($changed_permissions[$row['usrgrpid']] as $groupid => $permission) {
				if (!array_key_exists($row['ugsetid'], $ugset_permissions)
						|| !array_key_exists($groupid, $ugset_permissions[$row['ugsetid']])) {
					$ugset_permissions[$row['ugsetid']][$groupid]['new'] = $permission['new'];
					$ugset_permissions[$row['ugsetid']][$groupid]['old'] = $permission['old'];
					$ugset_permissions[$row['ugsetid']][$groupid]['usrgrp_count'] = 1;
				}
				else {
					if ($ugset_permissions[$row['ugsetid']][$groupid]['new'] != PERM_DENY
							&& ($permission['new'] > $ugset_permissions[$row['ugsetid']][$groupid]['new']
								|| $permission['new'] == PERM_DENY)) {
						$ugset_permissions[$row['ugsetid']][$groupid]['new'] = $permission['new'];
					}

					if ($permission['old'] == $ugset_permissions[$row['ugsetid']][$groupid]['old']) {
						$ugset_permissions[$row['ugsetid']][$groupid]['usrgrp_count']++;
					}
					elseif ($ugset_permissions[$row['ugsetid']][$groupid]['old'] != PERM_DENY
							&& ($permission['old'] > $ugset_permissions[$row['ugsetid']][$groupid]['old']
								|| $permission['old'] == PERM_DENY)) {
						$ugset_permissions[$row['ugsetid']][$groupid]['old'] = $permission['old'];
						$ugset_permissions[$row['ugsetid']][$groupid]['usrgrp_count'] = 1;
					}
				}
			}
		}

		return $ugset_permissions;
	}

	private static function getDbUgSetPermissions(array $ugset_permissions): array {
		$db_ugset_permissions = array_fill_keys(array_keys($ugset_permissions), []);

		$result = DBselect(
			'SELECT ugg.ugsetid,ugg.usrgrpid,r.id,r.permission'.
			' FROM ugset_group ugg'.
			' JOIN rights r ON ugg.usrgrpid=r.groupid'.
			' WHERE '.dbConditionId('ugg.ugsetid', array_keys($ugset_permissions))
		);

		while ($row = DBfetch($result)) {
			if (!array_key_exists($row['ugsetid'], $db_ugset_permissions)
					|| !array_key_exists($row['id'], $db_ugset_permissions[$row['ugsetid']])) {
				$db_ugset_permissions[$row['ugsetid']][$row['id']]['old'] = $row['permission'];
				$db_ugset_permissions[$row['ugsetid']][$row['id']]['usrgrp_count'] = 1;
			}
			else {
				if ($row['permission'] == $db_ugset_permissions[$row['ugsetid']][$row['id']]['old']) {
					$db_ugset_permissions[$row['ugsetid']][$row['id']]['usrgrp_count']++;
				}
				elseif ($db_ugset_permissions[$row['ugsetid']][$row['id']]['old'] != PERM_DENY
					&& ($row['permission'] > $db_ugset_permissions[$row['ugsetid']][$row['id']]['old']
						|| $row['permission'] == PERM_DENY)) {
					$db_ugset_permissions[$row['ugsetid']][$row['id']]['old'] = $row['permission'];
					$db_ugset_permissions[$row['ugsetid']][$row['id']]['usrgrp_count'] = 1;
				}
			}
		}

		return $db_ugset_permissions;
	}

	private static function updatePermissions(array $ugset_permissions, array $db_ugset_permissions): void {
		$ins_permissions = [];
		$upd_permissions = [];
		$del_permissions = [];

		self::unsetUnhangedUgSetPermissions($ugset_permissions, $db_ugset_permissions);

		if (!$ugset_permissions) {
			return;
		}

		[$permissions, $db_permissions] = self::getPermissions($ugset_permissions, $db_ugset_permissions);

		if (!$permissions) {
			return;
		}

		foreach ($permissions as $ugsetid => $hgset_permissions) {
			foreach ($hgset_permissions as $hgsetid => $permission) {
				$db_permission = $db_permissions[$ugsetid][$hgsetid];

				if ($permission >= PERM_READ) {
					if ($db_permission >= PERM_READ) {
						if ($permission != $db_permission) {
							$upd_permissions[] = [
								'values' => ['permission' => $permission],
								'where' => ['ugsetid' => $ugsetid, 'hgsetid' => $hgsetid]
							];
						}
					}
					else {
						$ins_permissions[] = [
							'ugsetid' => $ugsetid,
							'hgsetid' => $hgsetid,
							'permission' => $permission
						];
					}
				}
				elseif ($db_permission >= PERM_READ) {
					$del_permissions[] = dbConditionId('ugsetid', [$ugsetid]).
						' AND '.dbConditionId('hgsetid', [$hgsetid]);
				}
			}
		}

		if ($del_permissions) {
			DBexecute('DELETE FROM permission WHERE ('.implode(') OR (', $del_permissions).')');
		}

		if ($upd_permissions) {
			DB::update('permission', $upd_permissions);
		}

		if ($ins_permissions) {
			DB::insert('permission', $ins_permissions, false);
		}
	}

	private static function unsetUnhangedUgSetPermissions(array &$ugset_permissions,
			array &$db_ugset_permissions): void {
		foreach ($ugset_permissions as $ugsetid => $group_permissions) {
			foreach ($group_permissions as $groupid => $permission) {
				$changed = false;

				if (!array_key_exists($groupid, $db_ugset_permissions[$ugsetid])) {
					$changed = true;
				}
				else {
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
