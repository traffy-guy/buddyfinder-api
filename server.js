// server.js — ActivityHub API + Real-time Chat (UPDATED)
require("dotenv").config();
const express    = require("express");
const cors       = require("cors");
const http       = require("http");
const { Server } = require("socket.io");
const connectDB  = require("./config/db");

const app    = express();
const server = http.createServer(app);        // wrap Express in raw HTTP server
const io     = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || "*",  // set FRONTEND_URL in .env
    methods: ["GET", "POST"],
  },
});

// ─── Connect DB ───────────────────────────────────────────────────
connectDB();

// ─── Middleware ───────────────────────────────────────────────────
app.use(cors({ origin: process.env.FRONTEND_URL || "*" }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ─── REST Routes ─────────────────────────────────────────────────
app.use("/api/auth",        require("./routes/auth"));
app.use("/api/users",       require("./routes/users"));
app.use("/api/connections", require("./routes/connections"));
app.use("/api/chat",        require("./routes/chat"));   // ← NEW

// ─── Socket.io Chat ───────────────────────────────────────────────
require("./socket/chatSocket")(io);             // ← NEW

// ─── Health ───────────────────────────────────────────────────────
app.get("/", (req, res) => res.json({ status: "ActivityHub API + Chat running 🚀" }));

// ─── Error handler ────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Something went wrong" });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`🚀 Server on port ${PORT}`));  // use server not app
