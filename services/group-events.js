const GROUP_EVENTS = Object.freeze({
  GROUP_CREATED: "group:created",
  GROUP_UPDATED: "group:updated",
  GROUP_DELETED: "group:deleted",
  MEMBER_ADDED: "group:member_added",
  MEMBER_REMOVED: "group:member_removed",
  MEMBER_LEFT: "group:member_left",
  ROLE_UPDATED: "group:role_updated",
  JOIN_REQUEST_CREATED: "group:join_request_created",
  JOIN_REQUEST_RESOLVED: "group:join_request_resolved",
  INVITE_LINK_CREATED: "group:invite_link_created",
  INVITE_LINK_REVOKED: "group:invite_link_revoked",
  MESSAGE_CREATED: "group:message_created",
  MESSAGE_UPDATED: "group:message_updated",
  MESSAGE_DELETED: "group:message_deleted",
  MESSAGE_REACTION_UPDATED: "group:message_reaction_updated",
  MESSAGE_RECEIPT_UPDATED: "group:message_receipt_updated",
  MESSAGE_PINNED: "group:message_pinned",
  MESSAGE_UNPINNED: "group:message_unpinned",
  TYPING_STARTED: "group:typing_started",
  TYPING_STOPPED: "group:typing_stopped",
});

module.exports = {
  GROUP_EVENTS,
};
