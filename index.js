const express = require("express");
const AWS = require("aws-sdk");
const admin = require("firebase-admin");

const app = express();
const port = process.env.PORT || 3000;

// Parse JSON bodies
app.use(express.json());

// Initialize Firebase Admin (make sure to provide your service account or use environment variables)
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.applicationDefault(), // or use admin.credential.cert(serviceAccount)
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

// Helper function to store OTP with an expiration (e.g., 5 minutes)
function storeOtp(email, otp, ttlSeconds = 300) {
  const expiration = Date.now() + ttlSeconds * 1000;
  otpStore.set(email, { otp, expiration });
}

// Helper function to verify OTP
function verifyOtp(email, otp) {
  const record = otpStore.get(email);
  if (!record) return false;
  if (Date.now() > record.expiration) {
    otpStore.delete(email);
    return false;
  }
  return record.otp.toString() === otp.toString();
}

// Endpoint to send OTP to email
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

    // Store the OTP in our in-memory store
    storeOtp(email, otpCode);

    // Define email parameters for SES
    const params = {
      Source: "support@jivahealth.in",
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
    // For demonstration, we return the OTP in the response.
    // In production, you might choose NOT to return it.
    return res.status(200).json({ success: true, otp: otpCode });
  } catch (error) {
    console.error("Error sending email via SES:", error);
    return res.status(500).json({ success: false, message: error.message });
  }
});

// Endpoint to reset password using OTP
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

    // Verify OTP from the in-memory store
    if (!verifyOtp(email, otp)) {
      return res
        .status(400)
        .json({ success: false, message: "Invalid or expired OTP." });
    }

    // Get the user by email using Firebase Admin SDK
    const userRecord = await admin.auth().getUserByEmail(email);

    // Update the user's password
    await admin.auth().updateUser(userRecord.uid, { password: newPassword });

    // Optionally, delete the OTP record after successful password update
    otpStore.delete(email);

    return res.status(200).json({ success: true });
  } catch (error) {
    console.error("Error resetting password:", error);
    return res.status(500).json({ success: false, message: error.message });
  }
});

// A simple endpoint to verify that the backend is running.
app.get("/", (req, res) => {
  res.send("OTP Backend is running.");
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
