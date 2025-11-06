const ROLES = {
  Admin: ["read", "write", "delete", "admin"],
  Editor: ["read", "write"],
  Viewer: ["read"],
};

class AuthorizationEnforcer {
  constructor(auditLogger) {
    this.auditLogger = auditLogger;
  }

  canAccess(user, resource, action) {
    if (!user) return false;
    const permissions = ROLES[user.role] || [];
    return permissions.includes(action);
  }

  requirePermission(action) {
    return (req, res, next) => {
      const user = req.session.user;
      const wantsJson =
        req.path.startsWith("/api/") ||
        (req.get("accept") || "").includes("application/json");

      const deny = (status, message) => {
        if (wantsJson) {
          return res.status(status).json({ error: message });
        }
        return res.status(status).send(message);
      };

      if (!user) {
        this.auditLogger.logUnauthorizedAccess(
          null,
          req.ip,
          action,
          "NOT_AUTHENTICATED"
        );
        return deny(401, "Authentification requise");
      }

      if (!this.canAccess(user, null, action)) {
        this.auditLogger.logUnauthorizedAccess(
          user.username,
          req.ip,
          action,
          "INSUFFICIENT_ROLE"
        );
        return deny(403, "Accès refusé");
      }

      next();
    };
  }
}

module.exports = AuthorizationEnforcer;
