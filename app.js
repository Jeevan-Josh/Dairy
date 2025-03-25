const express = require("express");
const path = require("path");
const bcrypt = require("bcryptjs");
const methodOverride = require("method-override");
const ejsMate = require("ejs-mate");
const session = require("express-session");
const { initializeApp, cert } = require("firebase-admin/app");
const { getFirestore } = require("firebase-admin/firestore");

const app = express();

// Middleware
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: true }));
app.use(methodOverride("_method"));
app.engine("ejs", ejsMate);
app.use(express.static(path.join(__dirname, "/public")));

// Session setup
app.use(
  session({
    secret: "secretKey123",
    resave: false,
    saveUninitialized: true,
  })
);

// Initialize Firebase Admin SDK
const serviceAccount = require("./key.json");
initializeApp({
  credential: cert(serviceAccount),
});
const db = getFirestore();

// Login and Signup Routes (unchanged)
app.get("/login", (req, res) => {
  res.render("users/login", { errorMessage: null });
});

app.get("/signUp", (req, res) => {
  res.render("users/signup", { errorMessage: null });
});

app.post("/signUp", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).render("users/signup", {
      errorMessage: "Email and password are required.",
    });
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const userRef = db.collection("users").where("email", "==", email);
    const snapshot = await userRef.get();

    if (!snapshot.empty) {
      return res.render("users/signup", {
        errorMessage: "Email already in use.",
      });
    }

    const docRef = await db.collection("users").add({
      email,
      password: hashedPassword,
    });

    req.session.userId = docRef.id;
    res.redirect("/dashboard");
  } catch (err) {
    console.error("Signup error:", err.message, err.stack);
    res.status(500).render("users/signup", {
      errorMessage: "Signup failed: " + err.message,
    });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.render("users/login", {
      errorMessage: "Email and password are required.",
    });
  }

  try {
    const userRef = db.collection("users").where("email", "==", email);
    const snapshot = await userRef.get();

    if (snapshot.empty) {
      return res.render("users/login", { errorMessage: "User not found." });
    }

    const userDoc = snapshot.docs[0];
    const match = await bcrypt.compare(password, userDoc.data().password);

    if (match) {
      req.session.userId = userDoc.id;
      res.redirect("/dashboard");
    } else {
      res.render("users/login", { errorMessage: "Incorrect password." });
    }
  } catch (err) {
    console.error("Login error:", err.message, err.stack);
    res
      .status(500)
      .render("users/login", { errorMessage: "Login failed: " + err.message });
  }
});

// Dashboard Route with Date Filter
app.get("/dashboard", async (req, res) => {
  try {
    const { filterDate } = req.query; // Get date from query params
    let query = db.collection("journalEntries").orderBy("date", "desc");

    if (filterDate) {
      const startOfDay = new Date(filterDate);
      startOfDay.setHours(0, 0, 0, 0);
      const endOfDay = new Date(filterDate);
      endOfDay.setHours(23, 59, 59, 999);

      query = query
        .where("date", ">=", startOfDay.toISOString())
        .where("date", "<=", endOfDay.toISOString());
    }

    const snapshot = await query.get();
    const entries = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
    res.render("templates/index", { entries, filterDate });
  } catch (err) {
    console.error("Dashboard error:", err.message, err.stack);
    res.status(500).send("Error loading dashboard");
  }
});

// Add New Journal Entry
app.post("/add", async (req, res) => {
  const { title, content } = req.body;
  await db.collection("journalEntries").add({
    title,
    content,
    date: new Date().toISOString(),
  });
  res.redirect("/dashboard");
});

// Delete Entry
app.post("/delete/:id", async (req, res) => {
  await db.collection("journalEntries").doc(req.params.id).delete();
  res.redirect("/dashboard");
});

// Start Server
const PORT = 8080;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
