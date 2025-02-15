const express = require("express");
const AWS = require("aws-sdk");

const app = express();
const port = process.env.PORT || 3000;

// Parse JSON bodies
app.use(express.json());

// Configure AWS SDK using environment variables
AWS.config.update({
  region: process.env.AWS_REGION,
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
});

const ses = new AWS.SES();

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

    // Define the email parameters
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
    return res.status(200).json({ success: true, otp: otpCode });
  } catch (error) {
    console.error("Error sending email via SES:", error);
    return res.status(500).json({ success: false, error: error.message });
  }
});

app.get("/", (req, res) => {
  res.send("OTP Backend is running.");
});

app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
