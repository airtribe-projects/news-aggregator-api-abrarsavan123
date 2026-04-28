const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const JWT_SECRET = process.env.JWT_SECRET || "news-aggregator-secret";
const NEWS_API_KEY = process.env.NEWS_API_KEY || "";
const SALT_ROUNDS = 10;

// In-memory user store
const users = [];

// ── Auth Middleware ──────────────────────────────────────────────────────────

function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token =
        authHeader && authHeader.startsWith("Bearer ")
            ? authHeader.split(" ")[1]
            : null;

    if (!token) {
        return res.status(401).json({ message: "Access token required" });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ message: "Invalid or expired token" });
    }
}

// ── Routes ───────────────────────────────────────────────────────────────────

// POST /users/signup
app.post("/users/signup", async (req, res) => {
    const { name, email, password, preferences } = req.body;

    if (!name || !email || !password) {
        return res
            .status(400)
            .json({ message: "Name, email, and password are required" });
    }

    const existingUser = users.find((u) => u.email === email);
    if (existingUser) {
        return res.status(400).json({ message: "Email already registered" });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);
    const user = {
        id: users.length + 1,
        name,
        email,
        password: hashedPassword,
        preferences: Array.isArray(preferences) ? preferences : [],
    };

    users.push(user);
    return res.status(200).json({ message: "User registered successfully" });
});

// POST /users/login
app.post("/users/login", async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res
            .status(400)
            .json({ message: "Email and password are required" });
    }

    const user = users.find((u) => u.email === email);
    if (!user) {
        return res.status(401).json({ message: "Invalid credentials" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
        return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
        expiresIn: "1h",
    });
    return res.status(200).json({ token });
});

// GET /users/preferences (protected)
app.get("/users/preferences", authenticateToken, (req, res) => {
    const user = users.find((u) => u.id === req.user.id);
    if (!user) {
        return res.status(404).json({ message: "User not found" });
    }
    return res.status(200).json({ preferences: user.preferences });
});

// PUT /users/preferences (protected)
app.put("/users/preferences", authenticateToken, (req, res) => {
    const { preferences } = req.body;

    if (!Array.isArray(preferences)) {
        return res
            .status(400)
            .json({ message: "Preferences must be an array" });
    }

    const user = users.find((u) => u.id === req.user.id);
    if (!user) {
        return res.status(404).json({ message: "User not found" });
    }

    user.preferences = preferences;
    return res
        .status(200)
        .json({ message: "Preferences updated", preferences });
});

// GET /news (protected)
app.get("/news", authenticateToken, async (req, res) => {
    const user = users.find((u) => u.id === req.user.id);
    if (!user) {
        return res.status(404).json({ message: "User not found" });
    }

    const preferences = user.preferences;

    // Try live NewsAPI when a key is configured
    if (NEWS_API_KEY) {
        try {
            const query =
                preferences.length > 0 ? preferences.join(" OR ") : "latest";
            const url = `https://newsapi.org/v2/everything?q=${encodeURIComponent(query)}&apiKey=${NEWS_API_KEY}&pageSize=10`;
            const apiRes = await fetch(url);
            const data = await apiRes.json();

            if (data.status === "ok") {
                return res.status(200).json({ news: data.articles });
            }
        } catch (_err) {
            // Fall through to mock data
        }
    }

    // Mock news fallback — one article per preference
    const mockNews =
        preferences.length > 0
            ? preferences.map((pref) => ({
                  title: `Mock news about ${pref}`,
                  description: `This is a mock article about ${pref}.`,
                  url: `https://example.com/news/${encodeURIComponent(pref)}`,
                  publishedAt: new Date().toISOString(),
                  source: { name: "Mock News" },
              }))
            : [
                  {
                      title: "Top stories today",
                      description: "This is a generic mock news article.",
                      url: "https://example.com/news/top",
                      publishedAt: new Date().toISOString(),
                      source: { name: "Mock News" },
                  },
              ];

    return res.status(200).json({ news: mockNews });
});

// ── Start server ─────────────────────────────────────────────────────────────

app.listen(3000, () => {
    console.log("News Aggregator API listening on port 3000");
});

module.exports = app;
