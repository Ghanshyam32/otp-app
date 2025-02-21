const express = require("express");
const AWS = require("aws-sdk");
const admin = require("firebase-admin");

const app = express();
const port = process.env.PORT || 3000;

// Parse JSON bodies
app.use(express.json());

/**
 * Initialize Firebase Admin explicitly with a service account.
 */
if (!admin.apps.length) {
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    projectId: process.env.FIREBASE_PROJECT_ID,
  });
}

// Configure AWS SDK using environment variables
AWS.config.update({
  region: process.env.AWS_REGION,
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

const ses = new AWS.SES();

// In-memory OTP storage: { normalizedEmail -> { otp, expiration } }
const otpStore = new Map();

// Helper function: Normalize email
function normalizeEmail(email) {
  return email.trim().toLowerCase();
}

// Helper function: Store OTP with expiration (default 5 minutes)
function storeOtp(email, otp, ttlSeconds = 300) {
  const normalizedEmail = normalizeEmail(email);
  const expiration = Date.now() + ttlSeconds * 1000;
  otpStore.set(normalizedEmail, { otp, expiration });
}

// Helper function: Verify OTP
function verifyOtp(email, otp) {
  const normalizedEmail = normalizeEmail(email);
  const record = otpStore.get(normalizedEmail);
  if (!record) return false;
  if (Date.now() > record.expiration) {
    otpStore.delete(normalizedEmail);
    return false;
  }
  return record.otp.toString() === otp.toString();
}

/**
 * Endpoint: /sendOtp
 * - Expects a JSON body: { "email": "user@example.com" }
 * - Generates a 6-digit OTP, stores it, sends it via AWS SES, and returns it (for testing).
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
    // Store the OTP using the normalized email
    storeOtp(email, otpCode);

    // Define email parameters for SES
    const params = {
      Source: "support@jivahealth.in", // Must be verified in AWS SES
      Destination: { ToAddresses: [email] },
      Message: {
        Subject: { Data: "Your Secure Login OTP - Jiva Health" },
        Body: {
          Html: {
            Data: `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8" />
</head>
<body style="font-family: Arial, sans-serif; color: #000;">
  <h3>Your Secure Login OTP</h3>
  <p>Dear User,</p>
  <p>Your One-Time Password (OTP) for secure login is:</p>
  <p style="font-size: 24px; font-weight: bold;">${otpCode}</p>
  <p>This OTP is valid for 5 minutes. Do not share it with anyone.</p>
  <p>If you didn't request this, please ignore this email.</p>
  <br/>
  <p>Best Regards,<br/>
  Jiva Health Support Team</p>
</body>
</html>
            `,
          },
          Text: {
            Data: `Dear User,

Your One-Time Password (OTP) for secure login is: ${otpCode}

This OTP is valid for 5 minutes. Do not share it with anyone.

If you didn't request this, please ignore this email.

Best Regards,
Jiva Health Support Team`,
          },
        },
      },
    };

    // Send email via SES
    await ses.sendEmail(params).promise();

    // For demonstration, return the OTP in the response (remove for production)
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
    let { email, otp } = req.body;
    console.log("Received email:", JSON.stringify(email));
    if (!email || !otp) {
      return res
        .status(400)
        .json({ success: false, message: "Email and OTP are required." });
    }

    // Normalize the email
    const normalizedEmail = normalizeEmail(email);
    console.log("Normalized email:", normalizedEmail);

    // Retrieve OTP record using normalized email
    const record = otpStore.get(normalizedEmail);
    if (!record) {
      return res.status(404).json({
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

    // Fetch user record using the normalized email
    let userRecord;
    try {
      userRecord = await admin.auth().getUserByEmail(normalizedEmail);
      console.log("Fetched user record:", userRecord);
    } catch (err) {
      console.error("Error fetching user by email:", err);
      return res
        .status(404)
        .json({ success: false, message: "User not found." });
    }

    // Generate a custom token using the fetched user's UID
    const customToken = await admin.auth().createCustomToken(userRecord.uid);
    // Remove OTP record after successful verification
    otpStore.delete(normalizedEmail);
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
    let { email, otp, newPassword } = req.body;
    if (!email || !otp || !newPassword) {
      return res.status(400).json({
        success: false,
        message: "Email, OTP, and newPassword are required.",
      });
    }
    // Normalize the email
    const normalizedEmail = normalizeEmail(email);
    if (!verifyOtp(normalizedEmail, otp)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid or expired OTP." });
    }
    const userRecord = await admin.auth().getUserByEmail(normalizedEmail);
    await admin.auth().updateUser(userRecord.uid, { password: newPassword });
    otpStore.delete(normalizedEmail);
    return res.status(200).json({ success: true });
  } catch (error) {
    console.error("Error resetting password:", error);
    return res.status(500).json({ success: false, message: error.message });
  }
});

app.get("/testListUsers", async (req, res) => {
  try {
    const listUsersResult = await admin.auth().listUsers();
    const allEmails = listUsersResult.users.map((u) => u.email);
    return res.json({ emails: allEmails });
  } catch (error) {
    console.error("Error listing users:", error);
    return res.status(500).json({ error: error.message });
  }
});

// Simple endpoint to verify that the backend is running.
app.get("/", (req, res) => {
  res.send("OTP Backend is running.");
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
