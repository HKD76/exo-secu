// security/audit.js
const fs = require("node:fs");
const path = require("node:path");

class SecurityAuditLogger {
  constructor(filePath) {
    this.filePath = path.resolve(filePath);
  }

  logEvent(eventType, user, ipAddress, severity = "INFO", details = {}) {
    const entry = {
      timestamp: new Date().toISOString(),
      event_type: eventType,
      user: user || "anonymous",
      ip_address: ipAddress || "unknown",
      severity,
      details,
    };

    fs.appendFile(this.filePath, JSON.stringify(entry) + "\n", (err) => {
      if (err) console.error("Error writing security log:", err);
    });
  }

  logLoginAttempt(user, ip, success, reason = null, attempts = null) {
    this.logEvent("LOGIN_ATTEMPT", user, ip, success ? "INFO" : "WARNING", {
      success,
      reason,
      attempts,
    });
  }

  logPermissionChange(adminUser, targetUser, oldRole, newRole, ip) {
    this.logEvent("PERMISSION_CHANGE", adminUser, ip, "INFO", {
      targetUser,
      oldRole,
      newRole,
    });
  }

  logUnauthorizedAccess(user, ip, action, reason) {
    this.logEvent("UNAUTHORIZED_ACCESS", user, ip, "WARNING", {
      action,
      reason,
    });
  }

  logAnomaly(type, user, ip, extra = {}) {
    this.logEvent("ANOMALY", user, ip, "CRITICAL", {
      type,
      ...extra,
    });
  }
}

module.exports = SecurityAuditLogger;
