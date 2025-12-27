/* ================= IMPORTS ================= */
const express = require("express");
const mysql = require("mysql2");
const session = require("express-session");
const bcrypt = require("bcrypt");
const { v4: uuidv4 } = require("uuid");
const cors = require("cors");
const path = require("path");

/* ================= EXPRESS APP ================= */
const app = express();

/* ================= MIDDLEWARE ================= */
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public")); // Ensure your HTML files are in a folder named 'public'

app.use(cors({ origin: "*", credentials: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "multi-tenant-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: false, // Set to true if using HTTPS
        maxAge: 24 * 60 * 60 * 1000 // Extended to 24 hours for testing
    } 
  })
);

/* ================= DATABASE CONNECTION ================= */
const db = mysql.createPool({
  host: process.env.DB_HOST || "localhost",
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "Anushka@13",
  database: process.env.DB_NAME || "multi_tenant_db",
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10
});

/* ================= ROUTES ================= */

// Home redirect
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "public", "login.html"));
});

// REGISTER ROUTE
app.post("/register", async (req, res) => {
  const { email, mobile, password } = req.body;

  if (!email || !mobile || !password) return res.status(400).send("All fields required");

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = uuidv4();

    const sql = "INSERT INTO users (id, email, mobile, password) VALUES (?, ?, ?, ?)";
    db.query(sql, [userId, email.trim(), mobile.trim(), hashedPassword], (err) => {
      if (err) {
        if (err.code === "ER_DUP_ENTRY") return res.status(409).send("User already exists");
        return res.status(500).send("Database error during registration");
      }
      res.redirect("/login.html");
    });
  } catch (err) {
    res.status(500).send("Internal server error");
  }
});

// LOGIN ROUTE
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) return res.status(400).send("Email and Password required");

  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [email.trim()], async (err, results) => {
    if (err) return res.status(500).send("Database error");
    if (results.length === 0) return res.status(401).send("Invalid email or password");

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    
    if (!match) return res.status(401).send("Invalid email or password");

    // SET SESSION DATA
    req.session.userId = user.id;
    req.session.email = user.email;
    req.session.mobile = user.mobile;

    // IMPORTANT: Save session before redirecting to avoid 401 on dashboard
    req.session.save((err) => {
      if (err) return res.status(500).send("Session error");
      res.redirect("/dashboard.html");
    });
  });
});

// DASHBOARD DATA API
app.get("/dashboard-data", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Not logged in" });
  }
  res.json({
    email: req.session.email,
    mobile: req.session.mobile
  });
});

// LOGOUT
app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect("/login.html");
  });
});

/* ================= START SERVER ================= */
const PORT = process.env.PORT || 2000;
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));