const bcrypt = require("bcrypt");

class AuthenticationEnforcer {
  constructor(auditLogger, sessionTimeoutMs = 30 * 60 * 1000) {
    this.auditLogger = auditLogger;
    this.sessionTimeoutMs = sessionTimeoutMs;
    this.failedAttempts = new Map();
  }

  async hashPassword(plainPassword) {
    const saltRounds = 12;
    return bcrypt.hash(plainPassword, saltRounds);
  }

  async verifyPassword(plainPassword, hash) {
    return bcrypt.compare(plainPassword, hash);
  }

  checkSession(req, res, next) {
    const user = req.session.user;
    const now = Date.now();

    if (!user) {
      return res.redirect("/login");
    }

    if (!req.session.lastActivity) {
      req.session.lastActivity = now;
      return next();
    }

    const diff = now - req.session.lastActivity;
    if (diff > this.sessionTimeoutMs) {
      const username = req.session.user?.username;
      const ipAddress = req.ip;
      req.session.destroy(() => {
        if (username) {
          this.auditLogger.logEvent(
            "SESSION_EXPIRED",
            username,
            ipAddress,
            "INFO"
          );
        }
        return res.redirect("/login?expired=1");
      });
    } else {
      req.session.lastActivity = now;
      next();
    }
  }

  _incrementFailedAttempts(key) {
    const current = this.failedAttempts.get(key) || 0;
    const updated = current + 1;
    this.failedAttempts.set(key, updated);
    return updated;
  }

  isLocked(key) {
    const attempts = this.failedAttempts.get(key) || 0;
    return attempts >= 5;
  }

  resetFailedAttempts(key) {
    this.failedAttempts.delete(key);
  }

  async handleLogin(req, res, usersDb) {
    const { username, password } = req.body;
    const ip = req.ip || req.connection.remoteAddress || "unknown";

    const key = `${username}:${ip}`;

    if (this.isLocked(key)) {
      this.auditLogger.logLoginAttempt(username, ip, false, "ACCOUNT_LOCKED");
      this.auditLogger.logAnomaly("BRUTE_FORCE", username, ip, { attempts: 5 });
      return res.status(429).render("login", {
        error: "Compte verrouillé après trop de tentatives.",
        message: null,
        username,
      });
    }

    const user = usersDb.find((u) => u.username === username);
    if (!user) {
      const attempts = this._incrementFailedAttempts(key);
      this.auditLogger.logLoginAttempt(
        username,
        ip,
        false,
        "USER_NOT_FOUND",
        attempts
      );
      if (attempts >= 5) {
        this.auditLogger.logAnomaly("BRUTE_FORCE", username, ip, { attempts });
      }
      return res.status(401).render("login", {
        error: "Identifiants invalides.",
        message: null,
        username,
      });
    }

    const ok = await this.verifyPassword(password, user.passwordHash);
    if (!ok) {
      const attempts = this._incrementFailedAttempts(key);
      this.auditLogger.logLoginAttempt(
        username,
        ip,
        false,
        "BAD_PASSWORD",
        attempts
      );
      if (attempts >= 5) {
        this.auditLogger.logAnomaly("BRUTE_FORCE", username, ip, { attempts });
      }
      return res.status(401).render("login", {
        error: "Identifiants invalides.",
        message: null,
        username,
      });
    }

    this.resetFailedAttempts(key);
    req.session.user = {
      id: user.id,
      username: user.username,
      role: user.role,
      email: user.email,
    };
    req.session.lastActivity = Date.now();

    this.auditLogger.logLoginAttempt(username, ip, true);
    return res.redirect("/dashboard");
  }
}

module.exports = AuthenticationEnforcer;
