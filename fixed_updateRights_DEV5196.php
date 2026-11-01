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

							$changed_permissions[$usrgrp['usrgrpid']][$right['id']] = $right['permission'];
						}
					}
					else {
						$ins_rights[] = [
							'groupid' => $usrgrp['usrgrpid'],
							'id' => $right['id'],
							'permission' => $right['permission']
						];

						if ($db_usrgrps !== null) {
							$changed_permissions[$usrgrp['usrgrpid']][$right['id']] = $right['permission'];
						}
					}
				}
				unset($right);

				foreach ($db_rights as $db_right) {
					$del_rightids[] = $db_right['rightid'];
					$changed_permissions[$usrgrp['usrgrpid']][$db_right['id']] = PERM_NONE;
				}
			}
			unset($usrgrp);
		}

		if ($changed_permissions) {
			$changed_ugset_permissions = self::getChangedUgSetPermissions($changed_permissions);

			if ($changed_ugset_permissions) {
				[$ugset_permissions, $db_ugset_permissions] =
					self::prepareUgSetPermissions($changed_ugset_permissions, $changed_permissions);

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

	private static function getChangedUgSetPermissions(array $changed_permissions): array {
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
					$ugset_permissions[$row['ugsetid']][$groupid] = $permission;
				}
				elseif ($ugset_permissions[$row['ugsetid']][$groupid] != PERM_DENY
						&& ($permission > $ugset_permissions[$row['ugsetid']][$groupid] || $permission == PERM_DENY)) {
					$ugset_permissions[$row['ugsetid']][$groupid] = $permission;
				}
			}
		}

		return $ugset_permissions;
	}

	private static function prepareUgSetPermissions(array $ugset_permissions, array $changed_permissions): array {
		$db_ugset_permissions = array_fill_keys(array_keys($ugset_permissions), []);

		$result = DBselect(
			'SELECT ugg.ugsetid,ugg.usrgrpid,r.id,r.permission'.
			' FROM ugset_group ugg'.
			' JOIN rights r ON ugg.usrgrpid=r.groupid'.
			' WHERE '.dbConditionId('ugg.ugsetid', array_keys($ugset_permissions))
		);

		while ($row = DBfetch($result)) {
			if (!array_key_exists($row['id'], $db_ugset_permissions[$row['ugsetid']])) {
				$db_ugset_permissions[$row['ugsetid']][$row['id']] = $row['permission'];
			}
			elseif ($db_ugset_permissions[$row['ugsetid']][$row['id']] != PERM_DENY
					&& ($row['permission'] > $db_ugset_permissions[$row['ugsetid']][$row['id']]
						|| $row['permission'] == PERM_DENY)) {
				$db_ugset_permissions[$row['ugsetid']][$row['id']] = $row['permission'];
			}

			if (!array_key_exists($row['id'], $ugset_permissions[$row['ugsetid']])
					|| (array_key_exists($row['usrgrpid'], $changed_permissions)
						&& array_key_exists($row['id'], $changed_permissions[$row['usrgrpid']]))) {
				continue;
			}

			if ($ugset_permissions[$row['ugsetid']][$row['id']] != PERM_DENY
					&& ($row['permission'] > $ugset_permissions[$row['ugsetid']][$row['id']]
						|| $row['permission'] == PERM_DENY)) {
				$ugset_permissions[$row['ugsetid']][$row['id']] = $row['permission'];
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

	private static function updatePermissions(array $ugset_permissions, array $db_ugset_permissions): void {
		$ins_permissions = [];
		$upd_permissions = [];
		$del_permissions = [];

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

	private static function getPermissions(array $ugset_permissions, array $db_ugset_permissions): array {
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

		$result = DBselect(
			'SELECT hgg.hgsetid,hgg.groupid'.
			' FROM hgset_group hgg'.
			' WHERE hgg.hgsetid IN('.
					'SELECT DISTINCT hgg1.hgsetid'.
					' FROM hgset_group hgg1'.
					' WHERE '.dbConditionId('hgg1.groupid', array_keys($groupids)).
				')'.
				' AND '.dbConditionId('hgg.groupid', array_keys($group_ugsetids))
		);

		while ($row = DBfetch($result)) {
			foreach ($group_ugsetids[$row['groupid']] as $ugsetid => $foo) {
				if (!array_key_exists($row['groupid'], $ugset_permissions[$ugsetid])
						&& !array_key_exists($row['groupid'], $db_ugset_permissions[$ugsetid])) {
					continue;
				}

				$permission = array_key_exists($row['groupid'], $ugset_permissions[$ugsetid])
					? $ugset_permissions[$ugsetid][$row['groupid']]
					: $db_ugset_permissions[$ugsetid][$row['groupid']];

				if (!array_key_exists($ugsetid, $permissions)
						|| !array_key_exists($row['hgsetid'], $permissions[$ugsetid])
						|| ($permissions[$ugsetid][$row['hgsetid']] != PERM_DENY
							&& ($permission > $permissions[$ugsetid][$row['hgsetid']] || $permission == PERM_DENY))) {
					$permissions[$ugsetid][$row['hgsetid']] = $permission;
				}

				$db_permission = array_key_exists($row['groupid'], $db_ugset_permissions[$ugsetid])
					? $db_ugset_permissions[$ugsetid][$row['groupid']]
					: PERM_NONE;

				if (!array_key_exists($ugsetid, $db_permissions)
						|| !array_key_exists($row['hgsetid'], $db_permissions[$ugsetid])
						|| ($db_permissions[$ugsetid][$row['hgsetid']] != PERM_DENY
							&& ($db_permission > $db_permissions[$ugsetid][$row['hgsetid']]
								|| $db_permission == PERM_DENY))) {
					$db_permissions[$ugsetid][$row['hgsetid']] = $db_permission;
				}
			}
		}

		return [$permissions, $db_permissions];
	}

	/**
	 * @param array      $usrgrps
	 * @param null|array $db_usrgrps
