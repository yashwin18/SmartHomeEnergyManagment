
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const twilio = require("twilio");
const { OAuth2Client } = require("google-auth-library");

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static("public"));

mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.log("Mongo Error:", err.message));

const User = mongoose.model("User", {
  fullName: String,
  email: String,
  userId: { type: String, unique: true },
  password: String,
  mobile: String,
  otp: String,
  otpExpiry: Date
});

const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

function generateToken(user) {
  return jwt.sign(
    { id: user._id, userId: user.userId },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

/* SEND OTP */
app.post("/send-mobile-otp", async (req, res) => {
  const { mobile } = req.body;

  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  await User.updateOne(
    { mobile },
    { otp, otpExpiry: Date.now() + 5 * 60 * 1000 },
    { upsert: true }
  );

  try {
    await twilioClient.messages.create({
      body: `Your OTP is ${otp}`,
      from: process.env.TWILIO_PHONE,
      to: mobile
    });
    res.json({ message: "OTP Sent" });
  } catch (err) {
    res.status(500).json({ message: "SMS Failed", error: err.message });
  }
});

/* VERIFY OTP */
app.post("/verify-mobile-otp", async (req, res) => {
  const { mobile, otp } = req.body;

  const user = await User.findOne({ mobile });

  if (!user || user.otp !== otp || user.otpExpiry < Date.now()) {
    return res.status(400).json({ message: "Invalid or Expired OTP" });
  }

  res.json({ message: "OTP Verified" });
});

/* REGISTER */
app.post("/register", async (req, res) => {
  const { name, email, userId, password, mobile } = req.body;

  const existingUser = await User.findOne({ userId });
  if (existingUser) {
    return res.status(400).json({ message: "User ID already exists" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  await User.create({
    fullName: name,
    email,
    userId,
    password: hashedPassword,
    mobile
  });

  res.json({ message: "Registered Successfully" });
});

/* LOGIN */
app.post("/login", async (req, res) => {
  const { userId, password } = req.body;

  const user = await User.findOne({ userId });

  if (!user) return res.status(400).json({ message: "User not found" });

  const valid = await bcrypt.compare(password, user.password);

  if (!valid) return res.status(400).json({ message: "Wrong password" });

  const token = generateToken(user);
  res.json({ token });
});

/* GOOGLE LOGIN */
app.post("/google-login", async (req, res) => {
  const { token } = req.body;

  const ticket = await googleClient.verifyIdToken({
    idToken: token,
    audience: process.env.GOOGLE_CLIENT_ID
  });

  const payload = ticket.getPayload();

  let user = await User.findOne({ email: payload.email });

  if (!user) {
    user = await User.create({
      fullName: payload.name,
      email: payload.email,
      userId: "user" + Math.floor(Math.random() * 10000),
      password: ""
    });
  }

  const jwtToken = generateToken(user);
  res.json({ token: jwtToken });
});

app.listen(process.env.PORT, () => {
  console.log("Server running on port " + process.env.PORT);
  console.log("Open in browser: http://localhost:" + process.env.PORT);
});
