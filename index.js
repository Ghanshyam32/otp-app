// Assuming you have already required express, admin, etc.
const express = require("express");
const AWS = require("aws-sdk");
const admin = require("firebase-admin");

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());

// Initialize Firebase Admin (ensure you have the proper credentials configured)
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.applicationDefault(),
  });
}

// For demonstration, assume you store OTPs in-memory (for production, use a persistent store)
const otpStore = new Map();

app.post("/sendOtp", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res
        .status(400)
        .json({ success: false, message: "Email is required" });
    }
    const otpCode = Math.floor(100000 + Math.random() * 900000);
    // Store OTP with expiration (e.g., 5 minutes)
    otpStore.set(email, {
      otp: otpCode,
      expiration: Date.now() + 5 * 60 * 1000,
    });

    // Send OTP email via AWS SES (code unchanged)
    // ... (Your SES code here) ...

    return res.status(200).json({ success: true, otp: otpCode });
  } catch (error) {
    console.error("Error sending email via SES:", error);
    return res.status(500).json({ success: false, message: error.message });
  }
});

// New endpoint: Verify OTP and generate a custom token.
app.post("/verifyOtpAndGenerateToken", async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) {
      return res
        .status(400)
        .json({ success: false, message: "Email and OTP are required." });
    }

    const record = otpStore.get(email);
    if (!record) {
      return res
        .status(404)
        .json({
          success: false,
          message: "No OTP request found for this email.",
        });
    }
    // Check if OTP matches and is not expired.
    if (
      record.otp.toString() !== otp.toString() ||
      Date.now() > record.expiration
    ) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid or expired OTP." });
    }

    // Retrieve the user using Firebase Admin SDK.
    const userRecord = await admin.auth().getUserByEmail(email);
    // Generate a custom token.
    const customToken = await admin.auth().createCustomToken(userRecord.uid);

    // Optionally, remove the OTP record.
    otpStore.delete(email);

    return res.status(200).json({ success: true, token: customToken });
  } catch (error) {
    console.error("Error in verifyOtpAndGenerateToken:", error);
    return res.status(500).json({ success: false, message: error.message });
  }
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
