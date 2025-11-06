const validator = require("validator");

class InputValidator {
  isValidEmail(email) {
    return validator.isEmail(email || "");
  }

  isValidPassword(password) {
    if (!password || password.length < 8) return false;
    const hasUpper = /[A-Z]/.test(password);
    const hasLower = /[a-z]/.test(password);
    const hasDigit = /\d/.test(password);
    const hasSpecial = /[^A-Za-z0-9]/.test(password);
    return hasUpper && hasLower && hasDigit && hasSpecial;
  }

  isValidUsername(username) {
    if (!username) return false;
    if (username.length < 3 || username.length > 20) return false;
    return /^[A-Za-z0-9]+$/.test(username);
  }

  isValidAge(age) {
    const n = Number(age);
    if (!Number.isInteger(n)) return false;
    return n >= 13 && n <= 120;
  }

  sanitizeHtml(input) {
    if (!input) return "";
    return input
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#x27;")
      .replaceAll("/", "&#x2F;");
  }

  detectSqlInjection(input) {
    if (!input) return false;
    const lowered = input.toLowerCase();

    const patterns = [
      /(\bor\b|\band\b)\s+1\s*=\s*1/,
      /;--/,
      /drop\s+table/,
      /union\s+select/,
      /insert\s+into/,
      /update\s+\w+\s+set/,
      /delete\s+from/,
    ];

    return patterns.some((re) => re.test(lowered));
  }
}

module.exports = InputValidator;
