// server.js — ActivityHub Complete Backend (single file, no subfolders needed)
require("dotenv").config();
const express    = require("express");
const cors       = require("cors");
const http       = require("http");
const { Server } = require("socket.io");
const mongoose   = require("mongoose");
const bcrypt     = require("bcryptjs");
const jwt        = require("jsonwebtoken");
const multer     = require("multer");
const cloudinary = require("cloudinary").v2;
const { CloudinaryStorage } = require("multer-storage-cloudinary");
const { body, validationResult } = require("express-validator");
const twilio     = require("twilio");

const app    = express();
const server = http.createServer(app);
const io     = new Server(server, {
  cors: { origin: process.env.FRONTEND_URL || "*", methods: ["GET","POST"] }
});

// ── MIDDLEWARE ────────────────────────────────────────────────────
app.use(cors({ origin: process.env.FRONTEND_URL || "*" }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── MONGODB ───────────────────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => { console.error("❌ MongoDB error:", err.message); process.exit(1); });

// ── CLOUDINARY ────────────────────────────────────────────────────
cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key:    process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});
const storage = new CloudinaryStorage({
  cloudinary,
  params: { folder: "buddyfinder/profiles", allowed_formats: ["jpg","jpeg","png","webp"] },
});
const upload = multer({ storage, limits: { fileSize: 5 * 1024 * 1024 } });

// ── TWILIO (optional — phone OTP only) ───────────────────────────
let twilioClient = null;
if (process.env.TWILIO_ACCOUNT_SID && process.env.TWILIO_AUTH_TOKEN) {
  twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
  console.log("✅ Twilio initialized");
} else {
  console.log("⚠️  Twilio not configured — phone OTP disabled");
}

// ══════════════════════════════════════════════════════════════════
// MODELS
// ══════════════════════════════════════════════════════════════════

// User
const userSchema = new mongoose.Schema({
  name:     { type: String, required: true, trim: true },
  email:    { type: String, unique: true, sparse: true, lowercase: true, trim: true },
  phone:    { type: String, unique: true, sparse: true, trim: true },
  password: { type: String, minlength: 6 },
  gender:   { type: String, enum: ["male","female","other"], required: true },
  photoURL: { type: String, default: "" },
  location: {
    type:        { type: String, enum: ["Point"], default: "Point" },
    coordinates: { type: [Number], default: [0,0] },
  },
  city:        { type: String, default: "" },
  activities:  { type: [String], default: [] },
  connections: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
  pushSubscription: { type: Object },
}, { timestamps: true });
userSchema.index({ location: "2dsphere" });
userSchema.pre("save", async function(next) {
  if (!this.isModified("password") || !this.password) return next();
  this.password = await bcrypt.hash(this.password, 12); next();
});
userSchema.methods.matchPassword = function(p) { return bcrypt.compare(p, this.password); };
userSchema.methods.toJSON = function() { const o = this.toObject(); delete o.password; return o; };
const User = mongoose.model("User", userSchema);

// ConnectionRequest
const connReqSchema = new mongoose.Schema({
  from:   { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  to:     { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  status: { type: String, enum: ["pending","accepted","rejected"], default: "pending" },
}, { timestamps: true });
connReqSchema.index({ from: 1, to: 1 }, { unique: true });
const ConnectionRequest = mongoose.model("ConnectionRequest", connReqSchema);

// Message
const messageSchema = new mongoose.Schema({
  roomId: { type: String, required: true, index: true },
  from:   { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  to:     { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  text:   { type: String, required: true, trim: true, maxlength: 2000 },
  read:   { type: Boolean, default: false },
}, { timestamps: true });
const getRoomId = (a, b) => [a.toString(), b.toString()].sort().join("_");
const Message = mongoose.model("Message", messageSchema);

// ══════════════════════════════════════════════════════════════════
// HELPERS
// ══════════════════════════════════════════════════════════════════
const signToken = (id) => jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || "7d" });

const protect = async (req, res, next) => {
  const h = req.headers.authorization;
  if (!h || !h.startsWith("Bearer ")) return res.status(401).json({ error: "Not authorized" });
  try {
    const decoded = jwt.verify(h.split(" ")[1], process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id).select("-password");
    if (!req.user) return res.status(401).json({ error: "User not found" });
    next();
  } catch { res.status(401).json({ error: "Token invalid" }); }
};

// ══════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ══════════════════════════════════════════════════════════════════
const authRouter = express.Router();

// POST /api/auth/signup
authRouter.post("/signup", [
  body("name").notEmpty(), body("email").isEmail(),
  body("password").isLength({ min: 6 }), body("gender").isIn(["male","female","other"]),
], async (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  const { name, email, password, phone, gender } = req.body;
  try {
    if (await User.findOne({ email })) return res.status(400).json({ error: "Email already registered" });
    const user = await User.create({ name, email, password, phone, gender });
    res.status(201).json({ token: signToken(user._id), user });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /api/auth/login
authRouter.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email }).select("+password");
    if (!user || !(await user.matchPassword(password)))
      return res.status(401).json({ error: "Invalid email or password" });
    res.json({ token: signToken(user._id), user });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /api/auth/phone/send-otp
authRouter.post("/phone/send-otp", async (req, res) => {
  const { phone } = req.body;
  if (!phone) return res.status(400).json({ error: "Phone required" });
  if (!twilioClient) return res.status(503).json({ error: "Phone OTP not configured" });
  try {
    await twilioClient.verify.v2.services(process.env.TWILIO_VERIFY_SID)
      .verifications.create({ to: phone, channel: "sms" });
    res.json({ message: "OTP sent" });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /api/auth/phone/verify-otp
authRouter.post("/phone/verify-otp", async (req, res) => {
  const { phone, otp, name, gender } = req.body;
  if (!phone || !otp) return res.status(400).json({ error: "Phone and OTP required" });
  if (!twilioClient) return res.status(503).json({ error: "Phone OTP not configured" });
  try {
    const check = await twilioClient.verify.v2.services(process.env.TWILIO_VERIFY_SID)
      .verificationChecks.create({ to: phone, code: otp });
    if (check.status !== "approved") return res.status(400).json({ error: "Invalid OTP" });
    let user = await User.findOne({ phone });
    if (!user) {
      if (!name || !gender) return res.status(400).json({ error: "Name and gender required for new users" });
      user = await User.create({ phone, name, gender });
    }
    res.json({ token: signToken(user._id), user });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET /api/auth/me
authRouter.get("/me", protect, (req, res) => res.json(req.user));

app.use("/api/auth", authRouter);

// ══════════════════════════════════════════════════════════════════
// USER ROUTES
// ══════════════════════════════════════════════════════════════════
const usersRouter = express.Router();

// GET /api/users/nearby
usersRouter.get("/nearby", protect, async (req, res) => {
  const { radius = 10, activity } = req.query;
  const { coordinates } = req.user.location;
  if (!coordinates || (coordinates[0] === 0 && coordinates[1] === 0))
    return res.status(400).json({ error: "Update your location first" });
  try {
    const filter = {
      _id: { $ne: req.user._id },
      location: { $near: { $geometry: { type:"Point", coordinates }, $maxDistance: Number(radius)*1000 } },
    };
    if (activity) filter.activities = activity;
    const users = await User.find(filter).select("name photoURL gender city activities location").limit(50);
    res.json(users);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// GET /api/users/:id
usersRouter.get("/:id", protect, async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select("name photoURL gender city activities connections");
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// PUT /api/users/profile
usersRouter.put("/profile", protect, async (req, res) => {
  const allowed = ["name","gender","city","activities"];
  const updates = {};
  allowed.forEach(f => { if (req.body[f] !== undefined) updates[f] = req.body[f]; });
  try {
    const user = await User.findByIdAndUpdate(req.user._id, updates, { new: true, runValidators: true });
    res.json(user);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// PUT /api/users/location
usersRouter.put("/location", protect, async (req, res) => {
  const { latitude, longitude, city } = req.body;
  if (!latitude || !longitude) return res.status(400).json({ error: "latitude and longitude required" });
  try {
    const user = await User.findByIdAndUpdate(req.user._id,
      { location: { type:"Point", coordinates:[longitude, latitude] }, city: city || req.user.city },
      { new: true }
    );
    res.json({ message: "Location updated", user });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// POST /api/users/photo
usersRouter.post("/photo", protect, upload.single("photo"), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: "No file uploaded" });
  try {
    const user = await User.findByIdAndUpdate(req.user._id, { photoURL: req.file.path }, { new: true });
    res.json({ photoURL: user.photoURL });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.use("/api/users", usersRouter);

// ══════════════════════════════════════════════════════════════════
// CONNECTIONS ROUTES
// ══════════════════════════════════════════════════════════════════
const connRouter = express.Router();

connRouter.post("/request/:toId", protect, async (req, res) => {
  const fromId = req.user._id, toId = req.params.toId;
  if (fromId.toString() === toId) return res.status(400).json({ error: "Cannot connect with yourself" });
  try {
    const exists = await ConnectionRequest.findOne({ from: fromId, to: toId });
    if (exists) return res.status(400).json({ error: "Request already sent" });
    const request = await ConnectionRequest.create({ from: fromId, to: toId });
    res.status(201).json({ message: "Request sent", request });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

connRouter.get("/requests/incoming", protect, async (req, res) => {
  try {
    const requests = await ConnectionRequest.find({ to: req.user._id, status: "pending" })
      .populate("from", "name photoURL gender city activities");
    res.json(requests);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

connRouter.get("/requests/sent", protect, async (req, res) => {
  try {
    const requests = await ConnectionRequest.find({ from: req.user._id, status: "pending" })
      .populate("to", "name photoURL gender city");
    res.json(requests);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

connRouter.put("/accept/:requestId", protect, async (req, res) => {
  try {
    const request = await ConnectionRequest.findById(req.params.requestId);
    if (!request) return res.status(404).json({ error: "Request not found" });
    if (request.to.toString() !== req.user._id.toString()) return res.status(403).json({ error: "Not authorized" });
    request.status = "accepted"; await request.save();
    await User.findByIdAndUpdate(request.from, { $addToSet: { connections: request.to } });
    await User.findByIdAndUpdate(request.to,   { $addToSet: { connections: request.from } });
    res.json({ message: "Connection accepted" });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

connRouter.put("/reject/:requestId", protect, async (req, res) => {
  try {
    const request = await ConnectionRequest.findById(req.params.requestId);
    if (!request) return res.status(404).json({ error: "Not found" });
    request.status = "rejected"; await request.save();
    res.json({ message: "Request rejected" });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

connRouter.get("/friends", protect, async (req, res) => {
  try {
    const user = await User.findById(req.user._id).populate("connections", "name photoURL gender city activities");
    res.json(user.connections);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

connRouter.delete("/:friendId", protect, async (req, res) => {
  try {
    await User.findByIdAndUpdate(req.user._id, { $pull: { connections: req.params.friendId } });
    await User.findByIdAndUpdate(req.params.friendId, { $pull: { connections: req.user._id } });
    res.json({ message: "Connection removed" });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.use("/api/connections", connRouter);

// ══════════════════════════════════════════════════════════════════
// CHAT ROUTES
// ══════════════════════════════════════════════════════════════════
const chatRouter = express.Router();

chatRouter.get("/inbox", protect, async (req, res) => {
  try {
    const uid = req.user._id;
    const rooms = await Message.aggregate([
      { $match: { $or: [{ from: uid }, { to: uid }] } },
      { $sort: { createdAt: -1 } },
      { $group: { _id: "$roomId", lastMsg: { $first: "$$ROOT" } } },
      { $replaceRoot: { newRoot: "$lastMsg" } },
      { $sort: { createdAt: -1 } },
    ]);
    const inbox = await Promise.all(rooms.map(async msg => {
      const otherId = msg.from.toString() === uid.toString() ? msg.to : msg.from;
      const other = await User.findById(otherId).select("name photoURL city gender");
      const unread = await Message.countDocuments({ roomId: msg.roomId, to: uid, read: false });
      return { other, lastMsg: msg, unread };
    }));
    res.json(inbox);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

chatRouter.get("/history/:userId", protect, async (req, res) => {
  try {
    const roomId = getRoomId(req.user._id, req.params.userId);
    const page = parseInt(req.query.page) || 1;
    const msgs = await Message.find({ roomId }).sort({ createdAt: -1 }).skip((page-1)*40).limit(40).lean();
    await Message.updateMany({ roomId, to: req.user._id, read: false }, { $set: { read: true } });
    res.json(msgs.reverse());
  } catch(e) { res.status(500).json({ error: e.message }); }
});

chatRouter.get("/unread", protect, async (req, res) => {
  try {
    const count = await Message.countDocuments({ to: req.user._id, read: false });
    res.json({ count });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.use("/api/chat", chatRouter);

// ══════════════════════════════════════════════════════════════════
// SOCKET.IO — REAL-TIME CHAT
// ══════════════════════════════════════════════════════════════════
const onlineUsers = new Map();

io.use(async (socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error("Unauthorized"));
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select("name photoURL");
    if (!user) return next(new Error("User not found"));
    socket.user = user; next();
  } catch { next(new Error("Invalid token")); }
});

io.on("connection", (socket) => {
  const uid = socket.user._id.toString();
  onlineUsers.set(uid, socket.id);
  socket.join(uid);
  io.emit("user:online", { userId: uid });

  socket.on("message:send", async ({ toId, text }) => {
    if (!toId || !text?.trim()) return;
    try {
      const roomId = getRoomId(uid, toId);
      const msg = await Message.create({ roomId, from: socket.user._id, to: toId, text: text.trim() });
      const payload = { _id: msg._id, roomId, from: uid, to: toId, text: msg.text, createdAt: msg.createdAt, read: false, sender: { _id: socket.user._id, name: socket.user.name, photoURL: socket.user.photoURL } };
      io.to(toId).emit("message:receive", payload);
      socket.emit("message:sent", payload);
    } catch(e) { socket.emit("error", { message: e.message }); }
  });

  socket.on("typing:start", ({ toId }) => io.to(toId).emit("typing:start", { fromId: uid, name: socket.user.name }));
  socket.on("typing:stop",  ({ toId }) => io.to(toId).emit("typing:stop",  { fromId: uid }));

  socket.on("message:read", async ({ fromId }) => {
    const roomId = getRoomId(uid, fromId);
    await Message.updateMany({ roomId, to: uid, read: false }, { $set: { read: true } });
    io.to(fromId).emit("message:read", { byId: uid });
  });

  socket.on("disconnect", () => {
    onlineUsers.delete(uid);
    io.emit("user:offline", { userId: uid });
  });
});

// ── HEALTH ────────────────────────────────────────────────────────
app.get("/", (req, res) => res.json({ status: "BuddyFinder API running 🚀" }));

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: "Something went wrong" });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
