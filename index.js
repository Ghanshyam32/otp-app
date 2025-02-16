const express = require("express");
const AWS = require("aws-sdk");
const admin = require("firebase-admin");

const app = express();
const port = process.env.PORT || 3000;

// Parse JSON bodies
app.use(express.json());

// Initialize Firebase Admin (ensure you have the proper credentials configured)
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.applicationDefault(),
    // Optionally, add your Firestore databaseURL:
    // databaseURL: "https://your-project-id.firebaseio.com"
  });
}

// Configure AWS SDK using environment variables
AWS.config.update({
  region: process.env.AWS_REGION,
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

const ses = new AWS.SES();

// In-memory OTP storage: { email -> { otp, expiration } }
const otpStore = new Map();

// Helper function: Store OTP with expiration (default 5 minutes)
function storeOtp(email, otp, ttlSeconds = 300) {
  const expiration = Date.now() + ttlSeconds * 1000;
  otpStore.set(email, { otp, expiration });
}

// Helper function: Verify OTP
function verifyOtp(email, otp) {
  const record = otpStore.get(email);
  if (!record) return false;
  if (Date.now() > record.expiration) {
    otpStore.delete(email);
    return false;
  }
  return record.otp.toString() === otp.toString();
}

/**
 * Endpoint: /sendOtp
 * - Expects a JSON body: { "email": "user@example.com" }
 * - Generates a 6-digit OTP, stores it, sends it via SES, and returns it (for testing).
 */
app.post("/sendOtp", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res
        .status(400)
        .json({ success: false, message: "Email is required" });
    }
    // Generate a 6-digit OTP
    const otpCode = Math.floor(100000 + Math.random() * 900000);
    // Store the OTP in the in-memory store
    storeOtp(email, otpCode);

    // Define email parameters for SES
    const params = {
      Source: "support@jivahealth.in", // Must be verified in AWS SES
      Destination: { ToAddresses: [email] },
      Message: {
        Subject: { Data: "Your Secure Login OTP" },
        Body: {
          Html: {
            Data: `<p>Your OTP is: <strong>${otpCode}</strong></p>
                   <p>Do not share this OTP with anyone.</p>`,
          },
          Text: {
            Data: `Your OTP is: ${otpCode}. Do not share this OTP with anyone.`,
          },
        },
      },
    };

    // Send email via SES
    await ses.sendEmail(params).promise();
    // For testing, return the OTP in the response (remove in production)
    return res.status(200).json({ success: true, otp: otpCode });
  } catch (error) {
    console.error("Error sending email via SES:", error);
    return res.status(500).json({ success: false, message: error.message });
  }
});

/**
 * Endpoint: /verifyOtpAndGenerateToken
 * - Expects: { "email": "...", "otp": "..." }
 * - Verifies OTP and, if valid, generates and returns a custom token using Firebase Admin SDK.
 */
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
    // Remove OTP record
    otpStore.delete(email);
    return res.status(200).json({ success: true, token: customToken });
  } catch (error) {
    console.error("Error in verifyOtpAndGenerateToken:", error);
    return res.status(500).json({ success: false, message: error.message });
  }
});

/**
 * Endpoint: /resetPassword
 * - Expects: { "email": "...", "otp": "...", "newPassword": "..." }
 * - Verifies OTP and then updates the user's password using the Firebase Admin SDK.
 */
app.post("/resetPassword", async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) {
      return res
        .status(400)
        .json({
          success: false,
          message: "Email, OTP, and newPassword are required.",
        });
    }
    if (!verifyOtp(email, otp)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid or expired OTP." });
    }
    const userRecord = await admin.auth().getUserByEmail(email);
    await admin.auth().updateUser(userRecord.uid, { password: newPassword });
    otpStore.delete(email);
    return res.status(200).json({ success: true });
  } catch (error) {
    console.error("Error resetting password:", error);
    return res.status(500).json({ success: false, message: error.message });
  }
});

// Simple endpoint to verify that the backend is running.
app.get("/", (req, res) => {
  res.send("OTP Backend is running.");
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
