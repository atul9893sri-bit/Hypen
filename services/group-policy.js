const GROUP_ROLES = Object.freeze({
  OWNER: "owner",
  ADMIN: "admin",
  CO_ADMIN: "co_admin",
  MEMBER: "member",
});

const GROUP_PERMISSION_SCOPES = Object.freeze({
  ALL: "all",
  MEMBERS: "members",
  ADMINS: "admins",
  CO_ADMINS: "co_admins",
  OWNER: "owner",
});

const roleRank = {
  [GROUP_ROLES.OWNER]: 4,
  [GROUP_ROLES.ADMIN]: 3,
  [GROUP_ROLES.CO_ADMIN]: 2,
  [GROUP_ROLES.MEMBER]: 1,
};

function normalizeScope(scope) {
  if (scope === GROUP_PERMISSION_SCOPES.ALL) {
    return GROUP_PERMISSION_SCOPES.MEMBERS;
  }
  return scope || GROUP_PERMISSION_SCOPES.ADMINS;
}

function getGroupRole(group, chatId) {
  if (!group || !chatId) {
    return null;
  }
  if (group.ownerId === chatId) {
    return GROUP_ROLES.OWNER;
  }
  if (group.admins?.includes(chatId)) {
    return GROUP_ROLES.ADMIN;
  }
  if (group.coAdmins?.includes(chatId)) {
    return GROUP_ROLES.CO_ADMIN;
  }
  if (group.members?.includes(chatId)) {
    return GROUP_ROLES.MEMBER;
  }
  return null;
}

function roleHasMinimum(actorRole, requiredRole) {
  return (roleRank[actorRole] || 0) >= (roleRank[requiredRole] || 0);
}

function canPerformGroupAction({ group, actorId, permissionKey }) {
  const actorRole = getGroupRole(group, actorId);
  if (!actorRole) {
    return false;
  }

  const scope = normalizeScope(group?.settings?.[permissionKey]);
  if (scope === GROUP_PERMISSION_SCOPES.MEMBERS) {
    return true;
  }
  if (scope === GROUP_PERMISSION_SCOPES.CO_ADMINS) {
    return roleHasMinimum(actorRole, GROUP_ROLES.CO_ADMIN);
  }
  if (scope === GROUP_PERMISSION_SCOPES.ADMINS) {
    return roleHasMinimum(actorRole, GROUP_ROLES.ADMIN);
  }
  if (scope === GROUP_PERMISSION_SCOPES.OWNER) {
    return actorRole === GROUP_ROLES.OWNER;
  }
  return false;
}

function canManageParticipant({ group, actorId, targetId }) {
  const actorRole = getGroupRole(group, actorId);
  const targetRole = getGroupRole(group, targetId);

  if (!actorRole || !targetRole || actorId === targetId) {
    return false;
  }
  if (actorRole === GROUP_ROLES.OWNER) {
    return targetRole !== GROUP_ROLES.OWNER;
  }
  if (actorRole === GROUP_ROLES.ADMIN) {
    return [GROUP_ROLES.CO_ADMIN, GROUP_ROLES.MEMBER].includes(targetRole);
  }
  if (actorRole === GROUP_ROLES.CO_ADMIN) {
    return targetRole === GROUP_ROLES.MEMBER;
  }
  return false;
}

module.exports = {
  GROUP_PERMISSION_SCOPES,
  GROUP_ROLES,
  canManageParticipant,
  canPerformGroupAction,
  getGroupRole,
  roleHasMinimum,
};
