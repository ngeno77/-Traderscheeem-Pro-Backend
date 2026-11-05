
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { createClient } = require("@supabase/supabase-js");

const app = express();

app.use(cors({
  origin: process.env.FRONTEND_URL
    ? process.env.FRONTEND_URL.split(",").map(x => x.trim())
    : true
}));

app.use(express.json());

const PORT = process.env.PORT || 3000;

if (
  !process.env.SUPABASE_URL ||
  !process.env.SUPABASE_SERVICE_ROLE_KEY ||
  !process.env.JWT_SECRET
) {
  throw new Error("Missing required environment variables.");
}

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

const MPESA_BASE =
  process.env.MPESA_ENV === "production"
    ? "https://api.safaricom.co.ke"
    : "https://sandbox.safaricom.co.ke";

const CALLBACK_URL =
  process.env.MPESA_CALLBACK_URL ||
  "https://traderscheeem-pro-backend.onrender.com/api/mpesa/callback";

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "Traderscheeem Pro Backend is running!"
  });
});

app.get("/api/health", (req, res) => {
  res.json({ success: true, status: "online" });
});

// AUTHENTICATE USERS
function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : null;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Please log in first."
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.userId;
    next();
  } catch {
    return res.status(401).json({
      success: false,
      message: "Session expired. Please log in again."
    });
  }
}

// REGISTER
app.post("/api/auth/register", async (req, res) => {
  try {
    const { fullName, email, phone, password } = req.body;

    if (!fullName || !email || !phone || !password) {
      return res.status(400).json({
        success: false,
        message: "Please complete all fields."
      });
    }

    if (password.length < 4) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 4 characters."
      });
    }

    const normalizedEmail = email.trim().toLowerCase();

    const { data: existingUser, error: lookupError } =
      await supabase
        .from("users")
        .select("id")
        .eq("email", normalizedEmail)
        .maybeSingle();

    if (lookupError) throw lookupError;

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "Email is already registered."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const { data: user, error } = await supabase
      .from("users")
      .insert({
        full_name: fullName.trim(),
        email: normalizedEmail,
        phone: phone.trim(),
        password_hash: passwordHash
      })
      .select("id, full_name, email, phone")
      .single();

    if (error) throw error;

    return res.status(201).json({
      success: true,
      message: "Account created successfully.",
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        phone: user.phone
      }
    });

  } catch (error) {
    console.error("Registration error:", error);

    return res.status(500).json({
      success: false,
      message: "Registration failed. Please try again."
    });
  }
});

// LOGIN
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Enter your email and password."
      });
    }

    const { data: user, error } = await supabase
      .from("users")
      .select("id, full_name, email, phone, password_hash")
      .eq("email", email.trim().toLowerCase())
      .maybeSingle();

    if (error) throw error;

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({
        success: false,
        message: "Invalid email or password."
      });
    }

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    return res.json({
      success: true,
      message: "Login successful.",
      token,
      user: {
        id: user.id,
        fullName: user.full_name,
        email: user.email,
        phone: user.phone
      }
    });

  } catch (error) {
    console.error("Login error:", error);

    return res.status(500).json({
      success: false,
      message: "Login failed. Please try again."
    });
  }
});

// NORMALIZE KENYAN PHONE NUMBER
function normalizePhone(phone) {
  let value = String(phone || "").replace(/\D/g, "");

  if (value.startsWith("0")) {
    value = "254" + value.substring(1);
  }

  if (!/^254[71]\d{8}$/.test(value)) {
    throw new Error("Enter a valid Kenyan M-Pesa number.");
  }

  return value;
}

// GET SAFARICOM ACCESS TOKEN
async function getMpesaToken() {
  const key = process.env.MPESA_CONSUMER_KEY;
  const secret = process.env.MPESA_CONSUMER_SECRET;

  if (!key || !secret) {
    throw new Error("M-Pesa API credentials are missing.");
  }

  const credentials = Buffer
    .from(`${key}:${secret}`)
    .toString("base64");

  const response = await fetch(
    `${MPESA_BASE}/oauth/v1/generate?grant_type=client_credentials`,
    {
      headers: {
        Authorization: `Basic ${credentials}`
      }
    }
  );

  const data = await response.json();

  if (!response.ok || !data.access_token) {
    throw new Error("Could not authenticate with M-Pesa.");
  }

  return data.access_token;
}

// GENERATE STK PASSWORD
function getMpesaPassword() {
  const shortcode = process.env.MPESA_SHORTCODE;
  const passkey = process.env.MPESA_PASSKEY;

  if (!shortcode || !passkey) {
    throw new Error("M-Pesa shortcode or passkey is missing.");
  }

  const timestamp = new Date()
    .toISOString()
    .replace(/[-:TZ.]/g, "")
    .slice(0, 14);

  const password = Buffer
    .from(`${shortcode}${passkey}${timestamp}`)
    .toString("base64");

  return { timestamp, password };
}

// REQUEST M-PESA STK PUSH
app.post("/api/mpesa/stkpush", authenticate, async (req, res) => {
  let depositId;

  try {
    const amount = Number(req.body.amount);
    const phone = normalizePhone(req.body.phone);

    if (
      !Number.isInteger(amount) ||
      amount < 1600 ||
      amount > 130000
    ) {
      return res.status(400).json({
        success: false,
        message: "Deposit must be between KES 1,600 and KES 130,000."
      });
    }

    const { data: deposit, error: insertError } = await supabase
      .from("deposit_transactions")
      .insert({
        user_id: req.userId,
        phone,
        amount_kes: amount,
        status: "pending"
      })
      .select("id")
      .single();

    if (insertError) throw insertError;

    depositId = deposit.id;

    const accessToken = await getMpesaToken();
    const { timestamp, password } = getMpesaPassword();

    const shortcode = process.env.MPESA_SHORTCODE;

    const stkPayload = {
      BusinessShortCode: shortcode,
      Password: password,
      Timestamp: timestamp,
      TransactionType: "CustomerPayBillOnline",
      Amount: amount,
      PartyA: phone,
      PartyB: shortcode,
      PhoneNumber: phone,
      CallBackURL: CALLBACK_URL,
      AccountReference: "TRADERSCHEEEM",
      TransactionDesc: "Wallet Deposit"
    };

    const response = await fetch(
      `${MPESA_BASE}/mpesa/stkpush/v1/processrequest`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify(stkPayload)
      }
    );

    const result = await response.json();

    if (!response.ok || !result.CheckoutRequestID) {
      throw new Error(
        result.errorMessage ||
        result.ResponseDescription ||
        "M-Pesa could not start the payment."
      );
    }

    const { error: updateError } = await supabase
      .from("deposit_transactions")
      .update({
        checkout_request_id: result.CheckoutRequestID,
        merchant_request_id: result.MerchantRequestID || null
      })
      .eq("id", depositId);

    if (updateError) throw updateError;

    return res.json({
      success: true,
      message: "Payment request sent. Check your phone and enter your M-Pesa PIN.",
      depositId,
      checkoutRequestId: result.CheckoutRequestID
    });

  } catch (error) {
    console.error("STK Push error:", error);

    if (depositId) {
      await supabase
        .from("deposit_transactions")
        .update({ status: "failed" })
        .eq("id", depositId)
        .eq("status", "pending");
    }

    return res.status(400).json({
      success: false,
      message: error.message || "Unable to start M-Pesa payment."
    });
  }
});

// M-PESA CALLBACK
app.post("/api/mpesa/callback", async (req, res) => {
  // Acknowledge Safaricom's callback.
  res.json({ ResultCode: 0, ResultDesc: "Accepted" });

  try {
    const callback = req.body?.Body?.stkCallback;

    if (!callback?.CheckoutRequestID) return;

    const checkoutId = callback.CheckoutRequestID;
    const resultCode = String(callback.ResultCode);

    const { data: deposit, error } = await supabase
      .from("deposit_transactions")
      .select("id, status")
      .eq("checkout_request_id", checkoutId)
      .maybeSingle();

    if (error) throw error;
    if (!deposit || deposit.status !== "pending") return;

    // Failed or cancelled payments are not credited.
    if (resultCode !== "0") {
      await supabase.rpc("complete_mpesa_deposit", {
        p_checkout_request_id: checkoutId,
        p_result_code: resultCode,
        p_mpesa_receipt: null,
        p_callback_data: req.body
      });
      return;
    }

    // Verify successful callback with Safaricom STK Query.
    const accessToken = await getMpesaToken();
    const { timestamp, password } = getMpesaPassword();

    const queryResponse = await fetch(
      `${MPESA_BASE}/mpesa/stkpushquery/v1/query`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          BusinessShortCode: process.env.MPESA_SHORTCODE,
          Password: password,
          Timestamp: timestamp,
          CheckoutRequestID: checkoutId
        })
      }
    );

    const queryResult = await queryResponse.json();

    if (
      !queryResponse.ok ||
      String(queryResult.ResultCode) !== "0"
    ) {
      console.error("STK Query not confirmed:", queryResult);
      return;
    }

    const items =
      callback.CallbackMetadata?.Item || [];

    const receipt = items.find(
      item => item.Name === "MpesaReceiptNumber"
    )?.Value;

    if (!receipt) {
      console.error("Successful payment has no receipt number.");
      return;
    }

    const { error: creditError } = await supabase.rpc(
      "complete_mpesa_deposit",
      {
        p_checkout_request_id: checkoutId,
        p_result_code: "0",
        p_mpesa_receipt: String(receipt),
        p_callback_data: req.body
      }
    );

    if (creditError) throw creditError;

    console.log("Verified M-Pesa payment:", receipt);

  } catch (error) {
    console.error("M-Pesa callback processing error:", error);
  }
});

// CHECK WALLET BALANCE
app.get("/api/wallet", authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("users")
      .select("balance_kes")
      .eq("id", req.userId)
      .single();

    if (error) throw error;

    res.json({
      success: true,
      balanceKes: Number(data.balance_kes || 0)
    });

  } catch (error) {
    console.error("Wallet error:", error);

    res.status(500).json({
      success: false,
      message: "Could not load wallet balance."
    });
  }
});

// CHECK DEPOSIT STATUS
app.get("/api/mpesa/status/:id", authenticate, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("deposit_transactions")
      .select("id, amount_kes, status, mpesa_receipt, created_at")
      .eq("id", req.params.id)
      .eq("user_id", req.userId)
      .maybeSingle();

    if (error) throw error;

    if (!data) {
      return res.status(404).json({
        success: false,
        message: "Deposit not found."
      });
    }

    res.json({
      success: true,
      deposit: data
    });

  } catch (error) {
    console.error("Deposit status error:", error);

    res.status(500).json({
      success: false,
      message: "Could not check deposit status."
    });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
