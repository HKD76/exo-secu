require("dotenv").config();

const express = require("express");
const session = require("express-session");
const path = require("node:path");
const fs = require("node:fs");
const fsPromises = require("node:fs/promises");
const morgan = require("morgan");

const SecurityAuditLogger = require("./security/audit");
const AuthenticationEnforcer = require("./security/authentication");
const AuthorizationEnforcer = require("./security/authorization");
const InputValidator = require("./security/validation");

const app = express();
const PORT = process.env.PORT || 3001;
const SESSION_SECRET = process.env.SESSION_SECRET || "super-secret-key";
const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "user.json");
const ALLOWED_ROLES = new Set(["Admin", "Editor", "Viewer"]);

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(morgan("combined"));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 30 * 60 * 1000 },
  })
);

function loadUsers() {
  try {
    const raw = fs.readFileSync(USERS_FILE, "utf-8");
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      throw new TypeError("Le fichier utilisateurs n'est pas un tableau");
    }
    return parsed;
  } catch (error) {
    if (error.code === "ENOENT") {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      fs.writeFileSync(USERS_FILE, "[]", "utf-8");
      return [];
    }
    console.error("Erreur lors du chargement des utilisateurs:", error);
    return [];
  }
}

async function persistUsers(users) {
  await fsPromises.writeFile(
    USERS_FILE,
    JSON.stringify(users, null, 2),
    "utf-8"
  );
}

let users = loadUsers();

const auditLogger = new SecurityAuditLogger(
  path.join(__dirname, "security.log")
);
const authEnforcer = new AuthenticationEnforcer(auditLogger);
const authorizationEnforcer = new AuthorizationEnforcer(auditLogger);
const validator = new InputValidator();

app.get("/", (req, res) => {
  if (req.session.user) {
    return res.redirect("/dashboard");
  }
  return res.redirect("/login");
});

app.get("/login", (req, res) => {
  if (req.session.user) {
    return res.redirect("/dashboard");
  }

  let message = null;
  if (req.query.expired) {
    message = "Votre session a expiré. Veuillez vous reconnecter.";
  } else if (req.query.logout) {
    message = "Vous avez été correctement déconnecté.";
  }

  res.render("login", { error: null, message, username: "" });
});

app.post("/login", async (req, res, next) => {
  try {
    const username = (req.body.username || "").trim();
    const password = req.body.password || "";

    if (
      validator.detectSqlInjection(username) ||
      validator.detectSqlInjection(password)
    ) {
      auditLogger.logAnomaly("SQL_INJECTION", username, req.ip, {
        endpoint: "POST /login",
      });
      return res.status(400).render("login", {
        error: "Entrée invalide détectée.",
        message: null,
        username,
      });
    }

    req.body.username = username;
    return authEnforcer.handleLogin(req, res, users);
  } catch (error) {
    next(error);
  }
});

app.post("/logout", (req, res) => {
  const username = req.session.user?.username;
  req.session.destroy(() => {
    if (username) {
      auditLogger.logEvent("LOGOUT", username, null, "INFO");
    }
    res.redirect("/login?logout=1");
  });
});

app.get(
  "/dashboard",
  (req, res, next) => authEnforcer.checkSession(req, res, next),
  (req, res) => {
    const lastActivity = req.session.lastActivity
      ? new Date(req.session.lastActivity).toLocaleString("fr-FR")
      : "Inconnue";
    res.render("dashboard", { user: req.session.user, lastActivity });
  }
);

app.get(
  "/admin",
  (req, res, next) => authEnforcer.checkSession(req, res, next),
  authorizationEnforcer.requirePermission("admin"),
  (req, res) => {
    res.send("Zone administrateur réservée.");
  }
);

app.post(
  "/api/users",
  (req, res, next) => authEnforcer.checkSession(req, res, next),
  authorizationEnforcer.requirePermission("admin"),
  async (req, res, next) => {
    try {
      const { username, email, password, age, role = "Viewer" } = req.body;

      if (
        validator.detectSqlInjection(username) ||
        validator.detectSqlInjection(email) ||
        validator.detectSqlInjection(role)
      ) {
        auditLogger.logAnomaly(
          "SQL_INJECTION",
          req.session.user.username,
          req.ip,
          {
            endpoint: "POST /api/users",
          }
        );
        return res.status(400).json({ error: "Entrée invalide détectée" });
      }

      if (!validator.isValidUsername(username)) {
        return res.status(400).json({ error: "Nom d'utilisateur invalide" });
      }

      if (!validator.isValidEmail(email)) {
        return res.status(400).json({ error: "Email invalide" });
      }

      if (!validator.isValidPassword(password)) {
        return res.status(400).json({ error: "Mot de passe non conforme" });
      }

      if (!validator.isValidAge(age)) {
        return res.status(400).json({ error: "Âge invalide" });
      }

      if (!ALLOWED_ROLES.has(role)) {
        return res.status(400).json({ error: "Rôle inconnu" });
      }

      if (users.some((user) => user.username === username)) {
        return res
          .status(409)
          .json({ error: "Nom d'utilisateur déjà utilisé" });
      }

      if (users.some((user) => user.email === email)) {
        return res.status(409).json({ error: "Email déjà utilisé" });
      }

      const passwordHash = await authEnforcer.hashPassword(password);
      const nextId = users.length ? Math.max(...users.map((u) => u.id)) + 1 : 1;

      const newUser = {
        id: nextId,
        username,
        email,
        passwordHash,
        role,
      };

      users.push(newUser);
      await persistUsers(users);

      auditLogger.logPermissionChange(
        req.session.user.username,
        username,
        null,
        newUser.role,
        req.ip
      );

      res.status(201).json({ id: newUser.id, username: newUser.username });
    } catch (error) {
      next(error);
    }
  }
);

app.use((err, req, res, _next) => {
  console.error("Erreur non gérée:", err);
  auditLogger.logAnomaly(
    "UNHANDLED_EXCEPTION",
    req.session?.user?.username,
    req.ip,
    {
      message: err.message,
    }
  );
  if (req.accepts("json")) {
    res.status(500).json({ error: "Erreur interne du serveur" });
  } else {
    res.status(500).send("Erreur interne du serveur");
  }
});

app.listen(PORT, () => {
  console.log(`Security app JS running on http://localhost:${PORT}`);
});
