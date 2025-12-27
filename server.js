const express = require("express");
const mysql = require("mysql2");
const session = require("express-session");
const bcrypt = require("bcrypt");
const { v4: uuidv4 } = require("uuid");

const app = express();

/* ================= DATABASE CONNECTION ================= */

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "Anushka@13",
  database: "multi_tenant_db"
});

db.connect((err) => {
  if (err) {
    console.error("MySQL connection failed:", err);
    return;
  }
  console.log("Connected to MySQL Database");
});

/* ================= MIDDLEWARE ================= */

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));

app.use(
  session({
    secret: "multi-tenant-secret",
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 15 * 60 * 1000 } // 15 minutes
  })
);

/* ================= CREATE TABLE ================= */

const createUserTable = `
CREATE TABLE IF NOT EXISTS users (
  id VARCHAR(36) PRIMARY KEY unique,
  email VARCHAR(100) UNIQUE NOT NULL,
  mobile VARCHAR(15) UNIQUE NOT NULL,
  password VARCHAR(255) NOT NULL
);
`;

db.query(createUserTable, (err) => {
  if (err) console.error(err);
  else console.log("Users table ready");
});

/* ================= HOME ROUTE ================= */

app.get("/", (req, res) => {
  res.redirect("/login.html");
});

/* ================= LOGIN PAGE REDIRECT ================= */

app.get("/login", (req, res) => {
  res.redirect("/login.html");
});


/* ================= REGISTER ================= */

app.post("/register", async (req, res) => {
  const { email, mobile, password } = req.body;

  if (!email || !mobile || !password) {
    return res.send("All fields are required");
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const userId = uuidv4();

  const sql =
    "INSERT INTO users (id, email, mobile, password) VALUES (?, ?, ?, ?)";

 db.query(sql, [userId, email, mobile, hashedPassword], (err) => {
  if (err) {
    console.error("REGISTER ERROR:", err);
    return res.send(err.message);
  }
  res.redirect("/login.html");
});
});

/* ================= LOGIN ================= */

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  const sql = "SELECT * FROM users WHERE email = ?";

  db.query(sql, [email], async (err, results) => {
    if (err || results.length === 0) {
      return res.send("User not found");
    }

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      return res.send("Invalid password");
    }

    req.session.userId = user.id;
    req.session.email = user.email;
    req.session.mobile = user.mobile;

    res.redirect("/dashboard.html");
  });
});

/* ================= DASHBOARD DATA (FOR dashboard.html) ================= */

app.get("/dashboard-data", (req, res) => {
  if (!req.session.userId) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  res.json({
    email: req.session.email,
    mobile: req.session.mobile
  });
});

/* ================= LOGOUT ================= */

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/login.html");
  });
});

/* ================= START SERVER ================= */

app.listen(2000, () => {
  console.log("Server running at http://localhost:2000");
});
