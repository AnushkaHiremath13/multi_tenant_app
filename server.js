/* ================= IMPORTS ================= */
require('dotenv').config();
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const { v4: uuidv4 } = require("uuid");
const cors = require("cors");
const path = require("path");
const { Pool } = require("pg"); // 1. Use pg instead of mysql2

/* ================= EXPRESS APP ================= */
const app = express();

/* ================= MIDDLEWARE ================= */
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));

app.use(cors({ origin: "*", credentials: true }));

app.use(
  session({
    secret: process.env.SESSION_SECRET || "multi-tenant-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { 
        secure: process.env.NODE_ENV === "production", // Secure in production
        maxAge: 24 * 60 * 60 * 1000 
    } 
  })
);

/* ================= DATABASE CONNECTION (POSTGRES) ================= */
// 2. PostgreSQL Configuration
const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'postgres',
  password: String(process.env.DB_PASSWORD || ''), // Forces it to be a string even if empty
  database: process.env.DB_NAME || 'multi_tenant_db',
  port: process.env.DB_PORT || 5432,
  ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : false
});

/* DB TEST */
pool.connect((err, client, release) => {
  if (err) {
    console.error("❌ POSTGRES CONNECTION FAILED", err.stack);
  } else {
    console.log("✅ POSTGRES CONNECTED SUCCESSFULLY");
    release();
  }
});


/* ================= ROUTES ================= */

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

    // 3. Postgres uses $1, $2 syntax instead of ?
    const sql = "INSERT INTO users (id, email, mobile, password) VALUES ($1, $2, $3, $4)";
    await pool.query(sql, [userId, email.trim(), mobile.trim(), hashedPassword]);
    
    res.redirect("/login.html");
  } catch (err) {
    console.error(err);
    if (err.code === "23505") return res.status(409).send("User already exists"); // Postgres Unique Violation code
    res.status(500).send("Internal server error");
  }
});

// LOGIN ROUTE
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).send("Email and Password required");

  try {
    const sql = "SELECT * FROM users WHERE email = $1";
    const results = await pool.query(sql, [email.trim()]);

    if (results.rows.length === 0) return res.status(401).send("Invalid email or password");

    const user = results.rows[0];
    const match = await bcrypt.compare(password, user.password);
    
    if (!match) return res.status(401).send("Invalid email or password");

    req.session.userId = user.id;
    req.session.email = user.email;
    req.session.mobile = user.mobile;

    req.session.save((err) => {
      if (err) return res.status(500).send("Session error");
      res.redirect("/dashboard.html");
    });
  } catch (err) {
    res.status(500).send("Database error");
  }
});

app.get("/dashboard-data", (req, res) => {
  if (!req.session.userId) return res.status(401).json({ error: "Not logged in" });
  res.json({ email: req.session.email, mobile: req.session.mobile });
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('connect.sid');
    res.redirect("/login.html");
  });
});

/* ================= START SERVER ================= */
const PORT = process.env.PORT || 2000;
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));