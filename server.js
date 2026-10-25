require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const { Pool } = require("pg");
const admin = require("firebase-admin");

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json({ limit: "2mb" }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
});

const PORT = process.env.PORT || 8000;
const JWT_SECRET = process.env.JWT_SECRET || "dev-only-change-me";

// ============================================================
// FIREBASE
// ============================================================

let firebaseReady = false;

try {
  const raw = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

  if (raw) {
    const serviceAccount = require(
      require("path").resolve(raw)
    );

    admin.initializeApp({
      credential: admin.credential.cert(serviceAccount),
    });

    firebaseReady = true;
  }
} catch (e) {
  console.warn("Firebase push disabled:", e.message);
}

// ============================================================
// PUSH NOTIFICATIONS
// ============================================================

async function sendPushToUser(
  userId,
  title,
  body,
  data = {},
  type = "general"
) {
  try {
    await pool.query(
      `INSERT INTO notification_logs
       (user_id,title,body,type,data)
       VALUES($1,$2,$3,$4,$5)`,
      [
        userId,
        title,
        body,
        type,
        JSON.stringify(data),
      ]
    );

    if (!firebaseReady) return;

    const q = await pool.query(
      `SELECT token FROM push_tokens WHERE user_id=$1`,
      [userId]
    );

    if (!q.rowCount) return;

    const tokens = q.rows.map((r) => r.token);

    const resp =
      await admin.messaging().sendEachForMulticast({
        tokens,
        notification: {
          title,
          body,
        },
        data: Object.fromEntries(
          Object.entries(data).map(([k, v]) => [
            k,
            String(v),
          ])
        ),
      });

    const bad = [];

    resp.responses.forEach((r, i) => {
      if (
        !r.success &&
        (
          r.error?.code ===
            "messaging/registration-token-not-registered" ||
          r.error?.code ===
            "messaging/invalid-registration-token"
        )
      ) {
        bad.push(tokens[i]);
      }
    });

    if (bad.length) {
      await pool.query(
        `DELETE FROM push_tokens
         WHERE token=ANY($1::text[])`,
        [bad]
      );
    }
  } catch (e) {
    console.error("Push error:", e.message);
  }
}

// ============================================================
// BUSINESS CONSTANTS
// ============================================================

const DELIVERY_FEE = 30;
const DELIVERY_EARNING = 20;
const NEARKART_DELIVERY_SHARE = 10;
const CANCEL_SECONDS = 30;
const SETTLEMENT_DAYS = 7;

const money = (n) =>
  Number(Number(n).toFixed(2));

const commission = (sub) =>
  Math.floor(Number(sub) / 1000) * 10;

// ============================================================
// AUTH HELPERS
// ============================================================

function tokenFor(u) {
  return jwt.sign(
    {
      id: u.id,
      role: u.role,
      email: u.email,
    },
    JWT_SECRET,
    {
      expiresIn: "7d",
    }
  );
}

function auth(req, res, next) {
  try {
    const h = req.headers.authorization || "";

    if (!h.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "Login required",
      });
    }

    req.user = jwt.verify(
      h.slice(7),
      JWT_SECRET
    );

    next();
  } catch (e) {
    return res.status(401).json({
      error: "Invalid or expired token",
    });
  }
}

function roles(...allowed) {
  return (req, res, next) =>
    allowed.includes(req.user.role)
      ? next()
      : res.status(403).json({
          error: "Forbidden",
        });
}

function hashCode(v) {
  return crypto
    .createHash("sha256")
    .update(String(v))
    .digest("hex");
}

// ============================================================
// GMAIL OTP
// ============================================================

let transporter = null;

if (
  process.env.GMAIL_USER &&
  process.env.GMAIL_APP_PASSWORD
) {
  transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASSWORD,
    },
  });
}

async function sendOtp(email, code, purpose) {
  if (!transporter) {
    console.log(
      `[DEV OTP] ${email} -> ${code} (${purpose})`
    );
    return;
  }

  await transporter.sendMail({
    from: process.env.GMAIL_USER,
    to: email,
    subject: `NearKart ${purpose} OTP`,
    text:
      `Your NearKart OTP is ${code}. ` +
      `It is valid for 5 minutes and can be used once.`,
  });
}


 // ============================================================
 // ROOT + HEALTH
 // ============================================================

app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    message: "NearKart backend is running",
  });
});

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.status(200).json({
      ok: true,
      version: "2.1.0",
      database: "connected",
      pushNotifications: firebaseReady,
    });
  } catch (error) {
    console.error("Health check failed:", error.message);

    res.status(500).json({
      ok: false,
      message: "Database connection failed",
    });
  }
});

// ============================================================
// REQUEST OTP
// ============================================================

app.post(
  "/api/auth/request-otp",
  async (req, res) => {
    try {
      const {
        email,
        purpose = "login",
      } = req.body;

      if (!email) {
        return res.status(400).json({
          error: "Email required",
        });
      }

      const normalizedEmail =
        email.toLowerCase().trim();

      const allowedPurposes = [
        "login",
        "forgot_password",
        "register",
      ];

      if (!allowedPurposes.includes(purpose)) {
        return res.status(400).json({
          error: "Invalid OTP purpose",
        });
      }

      const code = String(
        Math.floor(
          100000 + Math.random() * 900000
        )
      );

      await pool.query(
        `INSERT INTO otp_codes
         (email,purpose,code_hash,expires_at)
         VALUES($1,$2,$3,NOW()+INTERVAL '5 minutes')`,
        [
          normalizedEmail,
          purpose,
          hashCode(code),
        ]
      );

      await sendOtp(
        normalizedEmail,
        code,
        purpose
      );

      res.json({
        message: "OTP sent to email",
      });
    } catch (e) {
      console.error(
        "Request OTP error:",
        e.message
      );

      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// VERIFY OTP
// ============================================================

app.post(
  "/api/auth/verify-otp",
  async (req, res) => {
    try {
      const {
        email,
        code,
        purpose = "login",
      } = req.body;

      if (!email || !code) {
        return res.status(400).json({
          error: "Email and OTP required",
        });
      }

      const normalizedEmail =
        email.toLowerCase().trim();

      const q = await pool.query(
        `SELECT *
         FROM otp_codes
         WHERE email=$1
           AND purpose=$2
           AND used=false
           AND expires_at>NOW()
         ORDER BY id DESC
         LIMIT 1`,
        [
          normalizedEmail,
          purpose,
        ]
      );

      if (!q.rowCount) {
        return res.status(400).json({
          error: "OTP expired or not found",
        });
      }

      const otp = q.rows[0];

      if (otp.attempts >= 5) {
        return res.status(429).json({
          error: "Too many attempts",
        });
      }

      if (
        otp.code_hash !==
        hashCode(code)
      ) {
        await pool.query(
          `UPDATE otp_codes
           SET attempts=attempts+1
           WHERE id=$1`,
          [otp.id]
        );

        return res.status(400).json({
          error: "Invalid OTP",
        });
      }

      // Mark OTP as used
      await pool.query(
        `UPDATE otp_codes
         SET used=true
         WHERE id=$1`,
        [otp.id]
      );

      // Forgot password OTP is NOT login OTP
      if (purpose === "forgot_password") {
        const userQ = await pool.query(
          `SELECT id,email,name,role
           FROM users
           WHERE email=$1`,
          [normalizedEmail]
        );

        if (!userQ.rowCount) {
          return res.status(404).json({
            error: "Account not found",
          });
        }

        return res.json({
          verified: true,
          purpose: "forgot_password",
          message:
            "OTP verified. You can now reset your password.",
        });
      }

      // Login OTP
      let u = (
        await pool.query(
          `SELECT *
           FROM users
           WHERE email=$1`,
          [normalizedEmail]
        )
      ).rows[0];

      // If user doesn't exist,
      // create customer account automatically.
      if (!u) {
        u = (
          await pool.query(
            `INSERT INTO users
             (role,name,email)
             VALUES('customer',$1,$2)
             RETURNING *`,
            [
              normalizedEmail.split("@")[0],
              normalizedEmail,
            ]
          )
        ).rows[0];
      }

      res.json({
        token: tokenFor(u),
        user: {
          id: u.id,
          role: u.role,
          name: u.name,
          email: u.email,
        },
      });
    } catch (e) {
      console.error(
        "Verify OTP error:",
        e.message
      );

      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// RESET PASSWORD USING GMAIL OTP
// ============================================================

app.post(
  "/api/auth/reset-password",
  async (req, res) => {
    try {
      const {
        email,
        code,
        newPassword,
      } = req.body;

      if (
        !email ||
        !code ||
        !newPassword
      ) {
        return res.status(400).json({
          error:
            "Email, OTP and new password are required",
        });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({
          error:
            "Password must be at least 6 characters",
        });
      }

      const normalizedEmail =
        email.toLowerCase().trim();

      // Find latest valid forgot-password OTP
      const q = await pool.query(
        `SELECT *
         FROM otp_codes
         WHERE email=$1
           AND purpose='forgot_password'
           AND used=false
           AND expires_at>NOW()
         ORDER BY id DESC
         LIMIT 1`,
        [normalizedEmail]
      );

      if (!q.rowCount) {
        return res.status(400).json({
          error:
            "OTP expired or not found",
        });
      }

      const otp = q.rows[0];

      if (otp.attempts >= 5) {
        return res.status(429).json({
          error: "Too many attempts",
        });
      }

      if (
        otp.code_hash !==
        hashCode(code)
      ) {
        await pool.query(
          `UPDATE otp_codes
           SET attempts=attempts+1
           WHERE id=$1`,
          [otp.id]
        );

        return res.status(400).json({
          error: "Invalid OTP",
        });
      }

      // Check account
      const userQ = await pool.query(
        `SELECT id
         FROM users
         WHERE email=$1`,
        [normalizedEmail]
      );

      if (!userQ.rowCount) {
        return res.status(404).json({
          error: "Account not found",
        });
      }

      // Hash new password
      const passwordHash =
        await bcrypt.hash(
          newPassword,
          12
        );

      // Update password
      await pool.query(
        `UPDATE users
         SET password_hash=$1
         WHERE email=$2`,
        [
          passwordHash,
          normalizedEmail,
        ]
      );

      // Mark OTP as used
      await pool.query(
        `UPDATE otp_codes
         SET used=true
         WHERE id=$1`,
        [otp.id]
      );

      res.json({
        message:
          "Password reset successfully",
      });
    } catch (e) {
      console.error(
        "Reset password error:",
        e.message
      );

      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// REGISTER
// ============================================================

app.post(
  "/api/auth/register",
  async (req, res) => {
    try {
      const {
        name,
        email,
        password,
        phone,
        role = "customer",
      } = req.body;

      if (
        !name ||
        !email ||
        !password
      ) {
        return res.status(400).json({
          error:
            "Name, email and password required",
        });
      }

      if (
        ![
          "customer",
          "shopkeeper",
          "delivery",
        ].includes(role)
      ) {
        return res.status(400).json({
          error: "Invalid role",
        });
      }

      const hash =
        await bcrypt.hash(
          password,
          12
        );

      const q = await pool.query(
        `INSERT INTO users
         (role,name,email,phone,password_hash)
         VALUES($1,$2,$3,$4,$5)
         RETURNING *`,
        [
          role,
          name,
          email.toLowerCase().trim(),
          phone || null,
          hash,
        ]
      );

      const u = q.rows[0];

      res.status(201).json({
        token: tokenFor(u),
        user: {
          id: u.id,
          role: u.role,
          name: u.name,
          email: u.email,
        },
      });
    } catch (e) {
      res.status(
        e.code === "23505"
          ? 409
          : 500
      ).json({
        error:
          e.code === "23505"
            ? "Email already registered"
            : e.message,
      });
    }
  }
);

// ============================================================
// PASSWORD LOGIN
// ============================================================

app.post(
  "/api/auth/login",
  async (req, res) => {
    try {
      const {
        email,
        password,
      } = req.body;

      const q = await pool.query(
        `SELECT *
         FROM users
         WHERE email=$1`,
        [email.toLowerCase().trim()]
      );

      if (
        !q.rowCount ||
        !q.rows[0].password_hash
      ) {
        return res.status(401).json({
          error: "Invalid login",
        });
      }

      const u = q.rows[0];

      if (
        !(await bcrypt.compare(
          password,
          u.password_hash
        ))
      ) {
        return res.status(401).json({
          error: "Invalid login",
        });
      }

      res.json({
        token: tokenFor(u),
        user: {
          id: u.id,
          role: u.role,
          name: u.name,
          email: u.email,
        },
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// PUSH TOKEN
// ============================================================

app.post(
  "/api/push/register-token",
  auth,
  async (req, res) => {
    try {
      const {
        token,
        platform,
      } = req.body;

      if (!token) {
        return res.status(400).json({
          error: "FCM token required",
        });
      }

      await pool.query(
        `INSERT INTO push_tokens
         (user_id,token,platform)
         VALUES($1,$2,$3)
         ON CONFLICT(token)
         DO UPDATE SET
           user_id=EXCLUDED.user_id,
           platform=EXCLUDED.platform,
           updated_at=NOW()`,
        [
          req.user.id,
          token,
          platform || null,
        ]
      );

      res.json({
        ok: true,
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

app.delete(
  "/api/push/register-token",
  auth,
  async (req, res) => {
    try {
      await pool.query(
        `DELETE FROM push_tokens
         WHERE user_id=$1
         AND token=$2`,
        [
          req.user.id,
          req.body.token,
        ]
      );

      res.json({
        ok: true,
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// NOTIFICATIONS
// ============================================================

app.get(
  "/api/notifications",
  auth,
  async (req, res) => {
    try {
      const q = await pool.query(
        `SELECT
           id,
           title,
           body,
           type,
           data,
           created_at
         FROM notification_logs
         WHERE user_id=$1
         ORDER BY created_at DESC
         LIMIT 50`,
        [req.user.id]
      );

      res.json(q.rows);
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// ADMIN BROADCAST
// ============================================================

app.post(
  "/api/admin/notifications/broadcast",
  auth,
  roles("admin"),
  async (req, res) => {
    try {
      const {
        title,
        body,
        type = "announcement",
        data = {},
        roles: targetRoles = [
          "customer",
          "shopkeeper",
          "delivery",
        ],
      } = req.body;

      if (
        !title ||
        !body ||
        !Array.isArray(targetRoles) ||
        !targetRoles.length
      ) {
        return res.status(400).json({
          error:
            "title, body and target roles required",
        });
      }

      const q = await pool.query(
        `SELECT id
         FROM users
         WHERE role=ANY($1::text[])`,
        [targetRoles]
      );

      for (const u of q.rows) {
        await sendPushToUser(
          u.id,
          title,
          body,
          data,
          type
        );
      }

      res.json({
        ok: true,
        recipients: q.rowCount,
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// NEARBY SHOPS
// ============================================================

app.get(
  "/api/shops/nearby",
  async (req, res) => {
    try {
      const lat = Number(
        req.query.lat
      );

      const lng = Number(
        req.query.lng
      );

      const radiusKm = Number(
        req.query.radiusKm || 10
      );

      if (
        !Number.isFinite(lat) ||
        !Number.isFinite(lng)
      ) {
        return res.status(400).json({
          error:
            "lat and lng are required",
        });
      }

      const q = await pool.query(
        `
        SELECT
          s.*,

          (
            6371 * acos(
              LEAST(
                1,
                GREATEST(
                  -1,

                  cos(radians($1))
                  * cos(radians(s.latitude))
                  * cos(
                      radians(s.longitude)
                      - radians($2)
                    )

                  + sin(radians($1))
                  * sin(radians(s.latitude))
                )
              )
            )
          ) AS distance_km,

          COALESCE(
            (
              SELECT COUNT(*)
              FROM products p
              WHERE p.shop_id=s.id
              AND p.active=true
            ),
            0
          ) AS product_count

        FROM shops s

        WHERE
          s.status='approved'
          AND s.latitude IS NOT NULL
          AND s.longitude IS NOT NULL

        HAVING
          (
            6371 * acos(
              LEAST(
                1,
                GREATEST(
                  -1,

                  cos(radians($1))
                  * cos(radians(s.latitude))
                  * cos(
                      radians(s.longitude)
                      - radians($2)
                    )

                  + sin(radians($1))
                  * sin(radians(s.latitude))
                )
              )
            )
          ) <= $3

        ORDER BY
          distance_km ASC,
          s.created_at DESC

        LIMIT 50
        `,
        [
          lat,
          lng,
          radiusKm,
        ]
      );

      res.json(q.rows);
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// ALL SHOPS
// ============================================================

app.get(
  "/api/shops",
  async (req, res) => {
    try {
      const q = await pool.query(
        `SELECT *
         FROM shops
         WHERE status='approved'
         ORDER BY created_at DESC`
      );

      res.json(q.rows);
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// PRODUCT SEARCH
// ============================================================

app.get(
  "/api/products/search",
  async (req, res) => {
    try {
      const qText = String(
        req.query.q || ""
      ).trim();

      const category = String(
        req.query.category || ""
      ).trim();

      const q = await pool.query(
        `
        SELECT
          p.*,
          s.shop_name,
          s.category AS shop_category

        FROM products p

        JOIN shops s
          ON s.id=p.shop_id

        WHERE
          p.active=true
          AND s.status='approved'

          AND (
            $1=''
            OR p.name ILIKE '%'||$1||'%'
            OR COALESCE(
                p.description,
                ''
              ) ILIKE '%'||$1||'%'
          )

          AND (
            $2=''
            OR p.category=$2
            OR s.category=$2
          )

        ORDER BY
          p.created_at DESC

        LIMIT 100
        `,
        [
          qText,
          category,
        ]
      );

      res.json(q.rows);
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// SHOP PRODUCTS
// ============================================================

app.get(
  "/api/shops/:id/products",
  async (req, res) => {
    try {
      const q = await pool.query(
        `SELECT *
         FROM products
         WHERE shop_id=$1
         AND active=true
         ORDER BY created_at DESC`,
        [req.params.id]
      );

      res.json(q.rows);
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// CREATE SHOP
// ============================================================

app.post(
  "/api/shops",
  auth,
  roles("shopkeeper"),
  async (req, res) => {
    try {
      const {
        shopName,
        category,
        gstNumber,
        panNumber,
        address,
        latitude,
        longitude,
        openingTime,
        closingTime,
        documents,
      } = req.body;

      const q = await pool.query(
        `INSERT INTO shops
         (
           owner_id,
           shop_name,
           category,
           gst_number,
           pan_number,
           address,
           latitude,
           longitude,
           opening_time,
           closing_time,
           documents
         )
         VALUES(
           $1,$2,$3,$4,$5,$6,
           $7,$8,$9,$10,$11
         )
         RETURNING *`,
        [
          req.user.id,
          shopName,
          category,
          gstNumber || null,
          panNumber || null,
          address || null,
          latitude || null,
          longitude || null,
          openingTime || null,
          closingTime || null,
          documents || {},
        ]
      );

      res.status(201).json(
        q.rows[0]
      );
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// CREATE PRODUCT
// ============================================================

app.post(
  "/api/shops/:id/products",
  auth,
  roles("shopkeeper", "admin"),
  async (req, res) => {
    try {
      const {
        name,
        description,
        category,
        price,
        stock,
        prescriptionRequired = false,
        images = [],
      } = req.body;

      const q = await pool.query(
        `INSERT INTO products
         (
           shop_id,
           name,
           description,
           category,
           price,
           stock,
           prescription_required,
           images
         )
         VALUES(
           $1,$2,$3,$4,
           $5,$6,$7,$8
         )
         RETURNING *`,
        [
          req.params.id,
          name,
          description || null,
          category || null,
          price,
          stock || 0,
          prescriptionRequired,
          JSON.stringify(images),
        ]
      );

      res.status(201).json(
        q.rows[0]
      );
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// CREATE ORDER
// ============================================================

app.post(
  "/api/orders",
  auth,
  roles("customer"),
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      const {
        shopId,
        items,
        address,
        prescriptionUrl,
      } = req.body;

      if (
        !shopId ||
        !Array.isArray(items) ||
        !items.length
      ) {
        return res.status(400).json({
          error:
            "shopId and items required",
        });
      }

      await client.query("BEGIN");

      const ids = items.map(
        (x) => x.productId
      );

      const pq =
        await client.query(
          `SELECT *
           FROM products
           WHERE id=ANY($1::uuid[])
           AND shop_id=$2
           AND active=true
           FOR UPDATE`,
          [
            ids,
            shopId,
          ]
        );

      if (
        pq.rowCount !==
        items.length
      ) {
        throw new Error(
          "Invalid products or mixed-shop order"
        );
      }

      let subtotal = 0;

      for (const item of items) {
        const p =
          pq.rows.find(
            (x) =>
              x.id ===
              item.productId
          );

        const qty = Number(
          item.quantity
        );

        if (
          !Number.isInteger(qty) ||
          qty < 1 ||
          qty > p.stock
        ) {
          throw new Error(
            `Invalid stock/quantity for ${p.name}`
          );
        }

        if (
          p.prescription_required &&
          !prescriptionUrl
        ) {
          throw new Error(
            "Prescription required"
          );
        }

        subtotal +=
          Number(p.price) * qty;
      }

      subtotal =
        money(subtotal);

      const comm =
        commission(subtotal);

      const total =
        money(
          subtotal +
            DELIVERY_FEE
        );

      const cancelUntil =
        new Date(
          Date.now() +
            CANCEL_SECONDS *
              1000
        );

      const oq =
        await client.query(
          `INSERT INTO orders
           (
             customer_id,
             shop_id,
             status,
             subtotal,
             delivery_fee,
             shop_commission,
             total,
             cancel_until,
             address,
             prescription_url
           )
           VALUES(
             $1,$2,'pending',
             $3,$4,$5,$6,
             $7,$8,$9
           )
           RETURNING *`,
          [
            req.user.id,
            shopId,
            subtotal,
            DELIVERY_FEE,
            comm,
            total,
            cancelUntil,
            address || {},
            prescriptionUrl ||
              null,
          ]
        );

      const order =
        oq.rows[0];

      for (const item of items) {
        const p =
          pq.rows.find(
            (x) =>
              x.id ===
              item.productId
          );

        await client.query(
          `INSERT INTO order_items
           (
             order_id,
             product_id,
             quantity,
             unit_price
           )
           VALUES($1,$2,$3,$4)`,
          [
            order.id,
            p.id,
            item.quantity,
            p.price,
          ]
        );

        await client.query(
          `UPDATE products
           SET stock=stock-$1
           WHERE id=$2`,
          [
            item.quantity,
            p.id,
          ]
        );
      }

      await client.query(
        `INSERT INTO financial_ledger
         (
           order_id,
           owner_type,
           owner_id,
           entry_type,
           amount,
           available_at
         )
         VALUES
         (
           $1,
           'shopkeeper',
           (
             SELECT owner_id
             FROM shops
             WHERE id=$2
           ),
           'shop_earning',
           $3,
           NOW()+INTERVAL '7 days'
         ),
         (
           $1,
           'nearkart',
           NULL,
           'shop_commission',
           $4,
           NOW()
         ),
         (
           $1,
           'delivery_pool',
           NULL,
           'delivery_earning',
           $5,
           NOW()+INTERVAL '7 days'
         ),
         (
           $1,
           'nearkart',
           NULL,
           'delivery_share',
           $6,
           NOW()
         )`,
        [
          order.id,
          shopId,
          money(
            subtotal -
              comm
          ),
          comm,
          DELIVERY_EARNING,
          NEARKART_DELIVERY_SHARE,
        ]
      );

      await client.query(
        `INSERT INTO payments
         (order_id,amount)
         VALUES($1,$2)`,
        [
          order.id,
          total,
        ]
      );

      await client.query(
        "COMMIT"
      );

      const ownerQ =
        await pool.query(
          `SELECT
             owner_id,
             shop_name
           FROM shops
           WHERE id=$1`,
          [shopId]
        );

      if (ownerQ.rowCount) {
        await sendPushToUser(
          ownerQ.rows[0]
            .owner_id,
          "New NearKart order",
          `New order #${String(
            order.id
          ).slice(0, 8)} received`,
          {
            orderId: order.id,
            status: "pending",
          },
          "new_order"
        );
      }

      await sendPushToUser(
        req.user.id,
        "NearKart order placed",
        "Your order has been placed successfully",
        {
          orderId: order.id,
          status: "pending",
        },
        "order_placed"
      );

      res.status(201).json({
        orderId: order.id,
        subtotal,
        deliveryFee:
          DELIVERY_FEE,
        total,
        shopkeeperReceives:
          money(
            subtotal - comm
          ),
        nearkartCommission:
          comm,
        deliveryPartnerReceives:
          DELIVERY_EARNING,
        cancellationEndsAt:
          cancelUntil,
        payment:
          "cashfree_required",
      });
    } catch (e) {
      await client.query(
        "ROLLBACK"
      );

      res.status(400).json({
        error: e.message,
      });
    } finally {
      client.release();
    }
  }
);

// ============================================================
// CANCEL ORDER
// ============================================================

app.post(
  "/api/orders/:id/cancel",
  auth,
  roles("customer"),
  async (req, res) => {
    const client =
      await pool.connect();

    try {
      await client.query(
        "BEGIN"
      );

      const q =
        await client.query(
          `SELECT *
           FROM orders
           WHERE id=$1
           AND customer_id=$2
           FOR UPDATE`,
          [
            req.params.id,
            req.user.id,
          ]
        );

      if (!q.rowCount) {
        return res.status(404).json({
          error:
            "Order not found",
        });
      }

      const o = q.rows[0];

      if (
        new Date() >
        new Date(
          o.cancel_until
        )
      ) {
        return res.status(400).json({
          error:
            "30-second cancellation window has ended",
        });
      }

      if (
        o.cancellation_status ===
        "cancelled"
      ) {
        return res.status(400).json({
          error:
            "Already cancelled",
        });
      }

      await client.query(
        `UPDATE orders
         SET
           status='cancelled',
           cancellation_status='cancelled',
           payment_status='refund_pending'
         WHERE id=$1`,
        [o.id]
      );

      await client.query(
        `UPDATE financial_ledger
         SET status='reversed'
         WHERE order_id=$1
         AND status='pending'`,
        [o.id]
      );

      await client.query(
        "COMMIT"
      );

      const shopQ =
        await pool.query(
          `SELECT s.owner_id
           FROM shops s
           JOIN orders o
             ON o.shop_id=s.id
           WHERE o.id=$1`,
          [o.id]
        );

      if (shopQ.rowCount) {
        await sendPushToUser(
          shopQ.rows[0]
            .owner_id,
          "Order cancelled",
          "Customer cancelled the order within 30 seconds",
          {
            orderId: o.id,
            status:
              "cancelled",
          },
          "order_cancelled"
        );
      }

      await sendPushToUser(
        req.user.id,
        "Order cancelled",
        "Refund has been queued for this eligible cancellation",
        {
          orderId: o.id,
          status:
            "refund_pending",
        },
        "refund_pending"
      );

      res.json({
        message:
          "Order cancelled; Cashfree refund must be initiated by the payment service",
        refundStatus:
          "pending",
      });
    } catch (e) {
      await client.query(
        "ROLLBACK"
      );

      res.status(500).json({
        error: e.message,
      });
    } finally {
      client.release();
    }
  }
);

// ============================================================
// ORDER STATUS
// ============================================================

app.post(
  "/api/orders/:id/status",
  auth,
  roles(
    "shopkeeper",
    "delivery",
    "admin"
  ),
  async (req, res) => {
    const allowed = [
      "accepted",
      "preparing",
      "ready",
      "assigned",
      "picked_up",
      "out_for_delivery",
      "delivered",
    ];

    const {
      status,
    } = req.body;

    if (!allowed.includes(status)) {
      return res.status(400).json({
        error:
          "Invalid status",
      });
    }

    const extra =
      status === "delivered"
        ? ", delivered_at=NOW()"
        : "";

    const q =
      await pool.query(
        `UPDATE orders
         SET status=$1${extra}
         WHERE id=$2
         RETURNING *`,
        [
          status,
          req.params.id,
        ]
      );

    if (!q.rowCount) {
      return res.status(404).json({
        error:
          "Order not found",
      });
    }

    const o = q.rows[0];

    const labels = {
      accepted:
        "Order accepted",
      preparing:
        "Order is being prepared",
      ready:
        "Order is ready",
      assigned:
        "Delivery partner assigned",
      picked_up:
        "Order picked up",
      out_for_delivery:
        "Order is out for delivery",
      delivered:
        "Order delivered",
    };

    await sendPushToUser(
      o.customer_id,
      "NearKart",
      labels[status] ||
        "Order updated",
      {
        orderId: o.id,
        status,
      },
      "order_status"
    );

    if (
      o.delivery_partner_id
    ) {
      await sendPushToUser(
        o.delivery_partner_id,
        "NearKart",
        labels[status] ||
          "Order updated",
        {
          orderId: o.id,
          status,
        },
        "order_status"
      );
    }

    res.json(o);
  }
);

// ============================================================
// ASSIGN DELIVERY PARTNER
// ============================================================

app.post(
  "/api/orders/:id/assign",
  auth,
  roles("admin"),
  async (req, res) => {
    const {
      deliveryPartnerId,
    } = req.body;

    const q =
      await pool.query(
        `UPDATE orders
         SET
           delivery_partner_id=$1,
           status='assigned'
         WHERE id=$2
         RETURNING *`,
        [
          deliveryPartnerId,
          req.params.id,
        ]
      );

    if (!q.rowCount) {
      return res.status(404).json({
        error:
          "Order not found",
      });
    }

    const o = q.rows[0];

    await sendPushToUser(
      o.customer_id,
      "NearKart",
      "Delivery partner assigned to your order",
      {
        orderId: o.id,
        status: "assigned",
      },
      "delivery_assigned"
    );

    await sendPushToUser(
      o.delivery_partner_id,
      "NearKart",
      "New delivery assigned",
      {
        orderId: o.id,
        status: "assigned",
      },
      "delivery_assigned"
    );

    res.json(o);
  }
);

// ============================================================
// DELIVERY LOCATION
// ============================================================

app.post(
  "/api/delivery/location",
  auth,
  roles("delivery"),
  async (req, res) => {
    const {
      orderId,
      latitude,
      longitude,
      accuracy,
    } = req.body;

    const own =
      await pool.query(
        `SELECT id
         FROM orders
         WHERE id=$1
         AND delivery_partner_id=$2
         AND status IN(
           'assigned',
           'picked_up',
           'out_for_delivery'
         )`,
        [
          orderId,
          req.user.id,
        ]
      );

    if (!own.rowCount) {
      return res.status(403).json({
        error:
          "Order not assigned",
      });
    }

    await pool.query(
      `INSERT INTO delivery_locations
       (
         order_id,
         delivery_partner_id,
         latitude,
         longitude,
         accuracy
       )
       VALUES($1,$2,$3,$4,$5)`,
      [
        orderId,
        req.user.id,
        latitude,
        longitude,
        accuracy || null,
      ]
    );

    res.json({
      ok: true,
    });
  }
);

// ============================================================
// LIVE LOCATION
// ============================================================

app.get(
  "/api/orders/:id/live-location",
  auth,
  async (req, res) => {
    const q =
      await pool.query(
        `SELECT
           latitude,
           longitude,
           accuracy,
           recorded_at
         FROM delivery_locations
         WHERE order_id=$1
         ORDER BY recorded_at DESC
         LIMIT 1`,
        [req.params.id]
      );

    if (!q.rowCount) {
      return res.status(404).json({
        error:
          "No live location yet",
      });
    }

    res.json(
      q.rows[0]
    );
  }
);

// ============================================================
// ADMIN ORDER EVENT
// ============================================================

app.post(
  "/api/admin/notifications/order-event",
  auth,
  roles("admin"),
  async (req, res) => {
    try {
      const {
        orderId,
        event,
      } = req.body;

      const q =
        await pool.query(
          `SELECT
             customer_id,
             delivery_partner_id
           FROM orders
           WHERE id=$1`,
          [orderId]
        );

      if (!q.rowCount) {
        return res.status(404).json({
          error:
            "Order not found",
        });
      }

      const o = q.rows[0];

      const map = {
        payment_success: [
          "Payment successful",
          "Your NearKart payment was successful",
          "payment_success",
        ],

        refund_initiated: [
          "Refund initiated",
          "Your eligible refund has been initiated",
          "refund_initiated",
        ],

        refund_success: [
          "Refund completed",
          "Your refund has been completed by the payment provider",
          "refund_success",
        ],

        complaint_update: [
          "Complaint updated",
          "There is an update on your support complaint",
          "complaint_update",
        ],
      };

      if (!map[event]) {
        return res.status(400).json({
          error:
            "Unsupported event",
        });
      }

      const [
        title,
        body,
        type,
      ] = map[event];

      await sendPushToUser(
        o.customer_id,
        title,
        body,
        {
          orderId,
          type,
        },
        type
      );

      res.json({
        ok: true,
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// ROUTE / DISTANCE / ETA
// ============================================================

app.get(
  "/api/orders/:id/route",
  auth,
  async (req, res) => {
    try {
      const q =
        await pool.query(
          `
          SELECT
            o.id,
            o.customer_id,
            o.delivery_partner_id,
            o.address,

            dl.latitude AS driver_latitude,
            dl.longitude AS driver_longitude

          FROM orders o

          LEFT JOIN LATERAL (
            SELECT
              latitude,
              longitude
            FROM delivery_locations
            WHERE order_id=o.id
            ORDER BY recorded_at DESC
            LIMIT 1
          ) dl ON TRUE

          WHERE o.id=$1
          `,
          [req.params.id]
        );

      if (!q.rowCount) {
        return res.status(404).json({
          error:
            "Order not found",
        });
      }

      const o = q.rows[0];

      const allowed =
        req.user.role === "admin" ||
        req.user.id ===
          o.customer_id ||
        req.user.id ===
          o.delivery_partner_id;

      if (!allowed) {
        return res.status(403).json({
          error:
            "Forbidden",
        });
      }

      if (
        o.driver_latitude ==
          null ||
        o.driver_longitude ==
          null
      ) {
        return res.status(404).json({
          error:
            "Driver GPS not available yet",
        });
      }

      const a =
        o.address || {};

      const destinationLat =
        Number(
          a.latitude ??
            a.lat
        );

      const destinationLng =
        Number(
          a.longitude ??
            a.lng ??
            a.lon
        );

      if (
        !Number.isFinite(
          destinationLat
        ) ||
        !Number.isFinite(
          destinationLng
        )
      ) {
        return res.status(400).json({
          error:
            "Order address is missing latitude/longitude",
        });
      }

      const coords =
        `${Number(
          o.driver_longitude
        )},${Number(
          o.driver_latitude
        )};${destinationLng},${destinationLat}`;

      const url =
        `https://router.project-osrm.org/route/v1/driving/` +
        `${encodeURIComponent(
          coords
        )}?overview=full&geometries=geojson&steps=false`;

      const r =
        await fetch(url, {
          headers: {
            "User-Agent":
              "NearKart/5.0 route service",
          },
        });

      if (!r.ok) {
        return res.status(502).json({
          error:
            "Routing service unavailable",
        });
      }

      const data =
        await r.json();

      if (
        data.code !== "Ok" ||
        !data.routes?.length
      ) {
        return res.status(400).json({
          error:
            data.message ||
            "No route found",
        });
      }

      const route =
        data.routes[0];

      res.json({
        distanceMeters:
          route.distance,

        distanceKm:
          Number(
            (
              route.distance /
              1000
            ).toFixed(2)
          ),

        durationSeconds:
          route.duration,

        etaMinutes:
          Math.max(
            1,
            Math.ceil(
              route.duration /
                60
            )
          ),

        driver: {
          latitude:
            Number(
              o.driver_latitude
            ),
          longitude:
            Number(
              o.driver_longitude
            ),
        },

        destination: {
          latitude:
            destinationLat,
          longitude:
            destinationLng,
        },

        geometry:
          route.geometry,
      });
    } catch (e) {
      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// ============================================================
// ADMIN FINANCIALS
// ============================================================

app.get(
  "/api/admin/financials",
  auth,
  roles("admin"),
  async (req, res) => {
    const q =
      await pool.query(
        `
        SELECT
          owner_type,
          entry_type,
          status,
          SUM(amount)::numeric(14,2)
            AS amount

        FROM financial_ledger

        GROUP BY
          owner_type,
          entry_type,
          status

        ORDER BY
          owner_type,
          entry_type,
          status
        `
      );

    res.json(q.rows);
  }
);

// ============================================================
// ADMIN SHOP DECISION
// ============================================================

app.post(
  "/api/admin/shops/:id/decision",
  auth,
  roles("admin"),
  async (req, res) => {
    const {
      status,
    } = req.body;

    if (
      ![
        "approved",
        "rejected",
        "suspended",
      ].includes(status)
    ) {
      return res.status(400).json({
        error:
          "Invalid decision",
      });
    }

    const q =
      await pool.query(
        `UPDATE shops
         SET status=$1
         WHERE id=$2
         RETURNING *`,
        [
          status,
          req.params.id,
        ]
      );

    res.json(
      q.rows[0] || null
    );
  }
);

// ============================================================
// ADMIN SETTLEMENT RELEASE
// ============================================================

app.post(
  "/api/admin/settlements/release",
  auth,
  roles("admin"),
  async (req, res) => {
    const q =
      await pool.query(
        `
        UPDATE financial_ledger

        SET status='available'

        WHERE
          status='pending'
          AND available_at<=NOW()

        RETURNING
          id,
          owner_type,
          owner_id,
          amount,
          order_id
        `
      );

    res.json({
      released: q.rows,
    });
  }
);

// ============================================================
// CUSTOMER ADDRESSES
// ============================================================

// Get all saved addresses for the logged-in customer
app.get(
  "/api/addresses",
  auth,
  roles("customer"),
  async (req, res) => {
    try {
      const q = await pool.query(
        `SELECT *
         FROM addresses
         WHERE user_id=$1
         ORDER BY is_default DESC, created_at DESC`,
        [req.user.id]
      );

      res.json(q.rows);
    } catch (e) {
      console.error("Get addresses error:", e.message);
      res.status(500).json({ error: e.message });
    }
  }
);

// Save a new address
app.post(
  "/api/addresses",
  auth,
  roles("customer"),
  async (req, res) => {
    const client = await pool.connect();

    try {
      const {
        fullName,
        phone,
        houseAddress,
        city,
        state,
        pincode,
        latitude,
        longitude,
        label = "Home",
        isDefault = false,
      } = req.body;

      if (
        !fullName ||
        !phone ||
        !houseAddress ||
        !city ||
        !state ||
        !pincode
      ) {
        return res.status(400).json({
          error:
            "Full name, phone, address, city, state and pincode are required",
        });
      }

      await client.query("BEGIN");

      // Only one default address per customer
      if (isDefault) {
        await client.query(
          `UPDATE addresses
           SET is_default=FALSE,
               updated_at=NOW()
           WHERE user_id=$1`,
          [req.user.id]
        );
      }

      const q = await client.query(
        `INSERT INTO addresses
         (
           user_id,
           full_name,
           phone,
           house_address,
           city,
           state,
           pincode,
           latitude,
           longitude,
           label,
           is_default
         )
         VALUES
         (
           $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11
         )
         RETURNING *`,
        [
          req.user.id,
          String(fullName).trim(),
          String(phone).trim(),
          String(houseAddress).trim(),
          String(city).trim(),
          String(state).trim(),
          String(pincode).trim(),
          latitude == null ? null : Number(latitude),
          longitude == null ? null : Number(longitude),
          String(label || "Home").trim(),
          Boolean(isDefault),
        ]
      );

      await client.query("COMMIT");

      res.status(201).json(q.rows[0]);
    } catch (e) {
      await client.query("ROLLBACK");

      console.error("Save address error:", e.message);

      res.status(500).json({
        error: e.message,
      });
    } finally {
      client.release();
    }
  }
);

// Delete one address belonging to the logged-in customer
app.delete(
  "/api/addresses/:id",
  auth,
  roles("customer"),
  async (req, res) => {
    try {
      const q = await pool.query(
        `DELETE FROM addresses
         WHERE id=$1
         AND user_id=$2
         RETURNING *`,
        [req.params.id, req.user.id]
      );

      if (!q.rowCount) {
        return res.status(404).json({
          error: "Address not found",
        });
      }

      res.json({
        message: "Address deleted",
        address: q.rows[0],
      });
    } catch (e) {
      console.error("Delete address error:", e.message);

      res.status(500).json({
        error: e.message,
      });
    }
  }
);

// Make an address the customer's default address
app.post(
  "/api/addresses/:id/default",
  auth,
  roles("customer"),
  async (req, res) => {
    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const check = await client.query(
        `SELECT id
         FROM addresses
         WHERE id=$1
         AND user_id=$2`,
        [req.params.id, req.user.id]
      );

      if (!check.rowCount) {
        await client.query("ROLLBACK");

        return res.status(404).json({
          error: "Address not found",
        });
      }

      // Remove old default address
      await client.query(
        `UPDATE addresses
         SET is_default=FALSE,
             updated_at=NOW()
         WHERE user_id=$1`,
        [req.user.id]
      );

      // Set selected address as default
      const q = await client.query(
        `UPDATE addresses
         SET is_default=TRUE,
             updated_at=NOW()
         WHERE id=$1
         AND user_id=$2
         RETURNING *`,
        [req.params.id, req.user.id]
      );

      await client.query("COMMIT");

      res.json(q.rows[0]);
    } catch (e) {
      await client.query("ROLLBACK");

      console.error("Default address error:", e.message);

      res.status(500).json({
        error: e.message,
      });
    } finally {
      client.release();
    }
  }
);

// ============================================================
// START SERVER
// ============================================================

/* ============================================================
   DELIVERY PARTNER MODULE - CORRECTED
   Uses existing users and orders tables
   ============================================================ */

async function ensureDeliverySchema() {
  // Delivery profile: name remains in users.name.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS delivery_partners (
      id BIGSERIAL UNIQUE,
      user_id UUID PRIMARY KEY
        REFERENCES users(id) ON DELETE CASCADE,
      bike_number VARCHAR(40),
      bike_model VARCHAR(120),
      license_number VARCHAR(80),
      profile_image TEXT,
      license_image TEXT,
      rc_image TEXT,
      insurance_image TEXT,
      bike_image TEXT,
      video_url TEXT,
      approval_status VARCHAR(20) NOT NULL DEFAULT 'pending'
        CHECK (approval_status IN ('pending','approved','rejected')),
      is_online BOOLEAN NOT NULL DEFAULT FALSE,
      current_latitude DOUBLE PRECISION,
      current_longitude DOUBLE PRECISION,
      last_location_at TIMESTAMPTZ,
      rejection_reason TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  await pool.query(`
    ALTER TABLE delivery_partners
    ADD COLUMN IF NOT EXISTS id BIGSERIAL
  `);

  
await pool.query(`
  ALTER TABLE delivery_partners
    ADD COLUMN IF NOT EXISTS user_id UUID,
    ADD COLUMN IF NOT EXISTS bike_number VARCHAR(40),
    ADD COLUMN IF NOT EXISTS bike_model VARCHAR(120),
    ADD COLUMN IF NOT EXISTS license_number VARCHAR(80),
    ADD COLUMN IF NOT EXISTS profile_image TEXT,
    ADD COLUMN IF NOT EXISTS license_image TEXT,
    ADD COLUMN IF NOT EXISTS rc_image TEXT,
    ADD COLUMN IF NOT EXISTS insurance_image TEXT,
    ADD COLUMN IF NOT EXISTS bike_image TEXT,
    ADD COLUMN IF NOT EXISTS video_url TEXT,
    ADD COLUMN IF NOT EXISTS approval_status VARCHAR(20) NOT NULL DEFAULT 'pending',
    ADD COLUMN IF NOT EXISTS is_online BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS current_latitude DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS current_longitude DOUBLE PRECISION,
    ADD COLUMN IF NOT EXISTS last_location_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS rejection_reason TEXT,
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
`);


  await pool.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS
    idx_delivery_partners_id
    ON delivery_partners(id)
  `);

  // Make orders.delivery_partner_id compatible with users.id.
  // If an older version stored delivery_partners.id (integer),
  // map it to delivery_partners.user_id before replacing it.
  const orderPartnerColumn = await pool.query(`
    SELECT data_type
    FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'orders'
      AND column_name = 'delivery_partner_id'
  `);

  if (!orderPartnerColumn.rowCount) {
    await pool.query(`
      ALTER TABLE orders
      ADD COLUMN delivery_partner_id UUID
    `);
  } else if (
    orderPartnerColumn.rows[0].data_type !== 'uuid'
  ) {
    const oldType = orderPartnerColumn.rows[0].data_type;

    if (!['integer', 'bigint', 'smallint'].includes(oldType)) {
      throw new Error(
        'orders.delivery_partner_id has an unsupported type: ' +
        oldType
      );
    }

    await pool.query(`
      ALTER TABLE orders
      ADD COLUMN IF NOT EXISTS delivery_partner_id_uuid UUID
    `);

    await pool.query(`
      UPDATE orders o
      SET delivery_partner_id_uuid = dp.user_id
      FROM delivery_partners dp
      WHERE dp.id = o.delivery_partner_id
        AND o.delivery_partner_id_uuid IS NULL
    `);

    await pool.query(`
      ALTER TABLE orders
      DROP COLUMN delivery_partner_id
    `);

    await pool.query(`
      ALTER TABLE orders
      RENAME COLUMN delivery_partner_id_uuid
      TO delivery_partner_id
    `);
  }

  // Earnings and withdrawals.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS delivery_transactions (
      id BIGSERIAL PRIMARY KEY,
      user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
      order_id INTEGER,
      amount NUMERIC(12,2) NOT NULL,
      type VARCHAR(30) NOT NULL,
      description TEXT,
      eligible_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      UNIQUE(order_id, type)
    )
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS delivery_withdrawal_requests (
      id BIGSERIAL PRIMARY KEY,
      user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
      amount NUMERIC(12,2) NOT NULL CHECK(amount > 0),
      bank_name VARCHAR(120) NOT NULL,
      account_holder VARCHAR(120) NOT NULL,
      account_number TEXT NOT NULL,
      ifsc VARCHAR(20) NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  // Correct types: order_id INTEGER, partner ID UUID.
  await pool.query(`
    CREATE TABLE IF NOT EXISTS delivery_locations (
      id BIGSERIAL PRIMARY KEY,
      order_id INTEGER,
      delivery_partner_id UUID NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
      latitude DOUBLE PRECISION NOT NULL,
      longitude DOUBLE PRECISION NOT NULL,
      accuracy DOUBLE PRECISION,
      recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);

  // Migrate an older delivery_locations table if necessary.
  const locationColumns = await pool.query(`
    SELECT column_name, data_type
    FROM information_schema.columns
    WHERE table_schema = current_schema()
      AND table_name = 'delivery_locations'
      AND column_name IN ('order_id', 'delivery_partner_id')
  `);

  const locationTypes = Object.fromEntries(
    locationColumns.rows.map(row => [
      row.column_name,
      row.data_type
    ])
  );

  if (
    locationTypes.delivery_partner_id &&
    locationTypes.delivery_partner_id !== 'uuid'
  ) {
    if (
      !['integer', 'bigint', 'smallint'].includes(
        locationTypes.delivery_partner_id
      )
    ) {
      throw new Error(
        'delivery_locations.delivery_partner_id has an unsupported type'
      );
    }

    await pool.query(`
      ALTER TABLE delivery_locations
      ADD COLUMN IF NOT EXISTS delivery_partner_id_uuid UUID
    `);

    await pool.query(`
      UPDATE delivery_locations dl
      SET delivery_partner_id_uuid = dp.user_id
      FROM delivery_partners dp
      WHERE dp.id = dl.delivery_partner_id
        AND dl.delivery_partner_id_uuid IS NULL
    `);

    await pool.query(`
      ALTER TABLE delivery_locations
      DROP COLUMN delivery_partner_id
    `);

    await pool.query(`
      ALTER TABLE delivery_locations
      RENAME COLUMN delivery_partner_id_uuid
      TO delivery_partner_id
    `);

    await pool.query(`
      ALTER TABLE delivery_locations
      ADD CONSTRAINT delivery_locations_partner_user_fk
      FOREIGN KEY (delivery_partner_id)
      REFERENCES users(id) ON DELETE CASCADE
    `);
  }

  if (locationTypes.order_id === 'uuid') {
    // Preserve rows whose old order IDs are numeric.
    await pool.query(`
      ALTER TABLE delivery_locations
      ADD COLUMN IF NOT EXISTS order_id_integer INTEGER
    `);

    await pool.query(`
      UPDATE delivery_locations
      SET order_id_integer = order_id::text::integer
      WHERE order_id IS NOT NULL
        AND order_id::text ~ '^[0-9]+$'
        AND order_id_integer IS NULL
    `);

    await pool.query(`
      ALTER TABLE delivery_locations DROP COLUMN order_id
    `);

    await pool.query(`
      ALTER TABLE delivery_locations
      RENAME COLUMN order_id_integer TO order_id
    `);
  }

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_delivery_offers
    ON orders(status, delivery_partner_id)
  `);

  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_delivery_location_latest
    ON delivery_locations(order_id, recorded_at DESC)
  `);
}

const deliveryOnly = (req, res, next) =>
  roles('delivery')(req, res, next);

const deliveryOrderSelect = `
  SELECT
    o.id,
    o.id::text AS order_number,
    u.name AS customer_name,
    u.phone AS customer_phone,
    COALESCE(s.shop_name, 'NearKart Shop') AS shop_name,
    COALESCE(s.address::text, 'Pickup address not added')
      AS pickup_address,
    COALESCE(o.address::text, 'Delivery address not added')
      AS delivery_address,
    COALESCE(o.total, 0) AS total_amount,
    COALESCE(o.delivery_fee, 30) AS delivery_fee,
    o.status,
    o.created_at,
    o.delivery_partner_id,
    CASE
      WHEN o.status = 'assigned' THEN 'accepted'
      WHEN o.status = 'out_for_delivery' THEN 'on_the_way'
      ELSE o.status
    END AS display_status
  FROM orders o
  LEFT JOIN users u ON u.id = o.customer_id
  LEFT JOIN shops s ON s.id = o.shop_id
`;

// ------------------------------------------------------------
// DELIVERY REGISTRATION
// ------------------------------------------------------------

app.post('/api/delivery/register', async (req, res) => {
  const {
    name,
    email,
    password,
    phone,
    bikeNumber,
    bikeModel,
    licenseNumber,
    profileImage,
    licenseImage,
    rcImage,
    insuranceImage,
    bikeImage,
    videoUrl
  } = req.body || {};

  if (
    !name || !email || !password || !phone ||
    String(password).length < 8 ||
    !bikeNumber || !bikeModel || !licenseNumber
  ) {
    return res.status(400).json({
      error:
        'Name, email, phone, password (8+ characters), ' +
        'bike number, bike model and licence number are required'
    });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const normalizedEmail = String(email).trim().toLowerCase();
    const normalizedPhone = String(phone).trim();
    const hash = await bcrypt.hash(String(password), 12);

    const result = await client.query(
      `INSERT INTO users
        (role, name, email, phone, password_hash)
       VALUES ('delivery', $1, $2, $3, $4)
       RETURNING id, name, email, phone, role`,
      [
        String(name).trim(),
        normalizedEmail,
        normalizedPhone,
        hash
      ]
    );

    const user = result.rows[0];

    await client.query(
      `INSERT INTO delivery_partners (
        user_id, bike_number, bike_model, license_number,
        profile_image, license_image, rc_image,
        insurance_image, bike_image, video_url
      )
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [
        user.id,
        String(bikeNumber).trim(),
        String(bikeModel).trim(),
        String(licenseNumber).trim(),
        profileImage || null,
        licenseImage || null,
        rcImage || null,
        insuranceImage || null,
        bikeImage || null,
        videoUrl || null
      ]
    );

    await client.query('COMMIT');

    res.status(201).json({
      message: 'Registration submitted. Admin approval is required before login.',
      deliveryPartner: {
        ...user,
        approval_status: 'pending',
        bike_number: bikeNumber,
        bike_model: bikeModel
      }
    });
  } catch (e) {
    await client.query('ROLLBACK');

    res.status(e.code === '23505' ? 409 : 500).json({
      error: e.code === '23505'
        ? 'Email or phone already registered'
        : e.message
    });
  } finally {
    client.release();
  }
});

// ------------------------------------------------------------
// DELIVERY LOGIN
// ------------------------------------------------------------

app.post('/api/delivery/login', async (req, res) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    const q = await pool.query(
      `SELECT
         u.id, u.name, u.email, u.phone,
         u.password_hash, u.role,
         dp.approval_status
       FROM users u
       JOIN delivery_partners dp ON dp.user_id = u.id
       WHERE LOWER(u.email) = $1
         AND u.role = 'delivery'`,
      [email]
    );

    if (
      !q.rowCount ||
      !q.rows[0].password_hash ||
      !(await bcrypt.compare(password, q.rows[0].password_hash))
    ) {
      return res.status(401).json({
        error: 'Invalid email or password'
      });
    }

    const user = q.rows[0];

    if (user.approval_status !== 'approved') {
      return res.status(403).json({
        error:
          `Account is ${user.approval_status}. ` +
          'Please wait for NearKart Admin approval.'
      });
    }

    res.json({
      token: tokenFor(user),
      deliveryBoy: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        approvalStatus: user.approval_status
      }
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ------------------------------------------------------------
// DELIVERY PROFILE - NAME COMES FROM users.name
// ------------------------------------------------------------

app.get('/api/delivery/profile', auth, deliveryOnly, async (req, res) => {
  try {
    const q = await pool.query(
      `SELECT
         u.id, u.name, u.email, u.phone,
         dp.bike_number, dp.bike_model, dp.license_number,
         dp.profile_image, dp.license_image, dp.rc_image,
         dp.insurance_image, dp.bike_image, dp.video_url,
         dp.approval_status, dp.is_online,
         dp.current_latitude, dp.current_longitude,
         dp.rejection_reason, dp.created_at
       FROM users u
       JOIN delivery_partners dp ON dp.user_id = u.id
       WHERE u.id = $1`,
      [req.user.id]
    );

    if (!q.rowCount) {
      return res.status(404).json({
        error: 'Delivery profile not found'
      });
    }

    res.json(q.rows[0]);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ------------------------------------------------------------
// ONLINE / OFFLINE
// ------------------------------------------------------------

app.patch('/api/delivery/availability', auth, deliveryOnly, async (req, res) => {
  try {
    if (typeof req.body.isOnline !== 'boolean') {
      return res.status(400).json({
        error: 'isOnline must be true or false'
      });
    }

    const q = await pool.query(
      `UPDATE delivery_partners
       SET is_online = $1, updated_at = NOW()
       WHERE user_id = $2
         AND approval_status = 'approved'
       RETURNING is_online`,
      [req.body.isOnline, req.user.id]
    );

    if (!q.rowCount) {
      return res.status(403).json({
        error: 'Admin approval required before going online'
      });
    }

    res.json({ isOnline: q.rows[0].is_online });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ------------------------------------------------------------
// ASSIGNED ORDERS
// ------------------------------------------------------------

app.get('/api/delivery/orders', auth, deliveryOnly, async (req, res) => {
  try {
    const q = await pool.query(
      `${deliveryOrderSelect}
       WHERE o.delivery_partner_id = $1
       ORDER BY o.created_at DESC`,
      [req.user.id]
    );

    res.json(q.rows.map(row => ({
      ...row,
      status: row.display_status
    })));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ------------------------------------------------------------
// AVAILABLE OFFERS
// ------------------------------------------------------------

app.get('/api/delivery/offers', auth, deliveryOnly, async (req, res) => {
  try {
    const partner = await pool.query(
      `SELECT is_online, approval_status
       FROM delivery_partners
       WHERE user_id = $1`,
      [req.user.id]
    );

    if (
      !partner.rowCount ||
      partner.rows[0].approval_status !== 'approved'
    ) {
      return res.status(403).json({
        error: 'Delivery account is not approved'
      });
    }

    if (!partner.rows[0].is_online) {
      return res.json([]);
    }

    const q = await pool.query(
      `${deliveryOrderSelect}
       WHERE o.delivery_partner_id IS NULL
         AND o.status = 'ready'
       ORDER BY o.created_at ASC
       LIMIT 50`
    );

    res.json(q.rows.map(row => ({
      ...row,
      status: row.display_status
    })));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ------------------------------------------------------------
// ACCEPT ORDER
// ------------------------------------------------------------

app.post('/api/delivery/orders/:id/accept', auth, deliveryOnly, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const partner = await client.query(
      `SELECT is_online, approval_status
       FROM delivery_partners
       WHERE user_id = $1`,
      [req.user.id]
    );

    if (
      !partner.rowCount ||
      partner.rows[0].approval_status !== 'approved' ||
      !partner.rows[0].is_online
    ) {
      await client.query('ROLLBACK');
      return res.status(403).json({
        error: 'You must be approved and online to accept orders'
      });
    }

    const q = await client.query(
      `UPDATE orders
       SET delivery_partner_id = $1,
           status = 'assigned'
       WHERE id = $2
         AND delivery_partner_id IS NULL
         AND status = 'ready'
       RETURNING id, customer_id, status`,
      [req.user.id, req.params.id]
    );

    if (!q.rowCount) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: 'Order was already assigned or is not ready'
      });
    }

    await client.query('COMMIT');

    const order = q.rows[0];

    await sendPushToUser(
      order.customer_id,
      'NearKart',
      'Delivery partner assigned to your order',
      { orderId: order.id, status: 'assigned' },
      'delivery_assigned'
    );

    res.json({
      id: order.id,
      status: 'accepted'
    });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

// ------------------------------------------------------------
// DELIVERY ORDER STATUS
// ------------------------------------------------------------

app.patch('/api/delivery/orders/:id/status', auth, deliveryOnly, async (req, res) => {
  const requested = String(req.body.status || '');

  const targetMap = {
    picked_up: 'picked_up',
    on_the_way: 'out_for_delivery',
    delivered: 'delivered'
  };

  const target = targetMap[requested];

  if (!target) {
    return res.status(400).json({
      error: 'Invalid delivery status'
    });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const old = await client.query(
      `SELECT id, customer_id, status
       FROM orders
       WHERE id = $1
         AND delivery_partner_id = $2
       FOR UPDATE`,
      [req.params.id, req.user.id]
    );

    if (!old.rowCount) {
      await client.query('ROLLBACK');
      return res.status(404).json({
        error: 'Assigned order not found'
      });
    }

    const current = old.rows[0].status;

    const allowed = {
      assigned: ['picked_up'],
      picked_up: ['out_for_delivery'],
      out_for_delivery: ['delivered']
    };

    if (!(allowed[current] || []).includes(target)) {
      await client.query('ROLLBACK');
      return res.status(409).json({
        error: `Cannot change ${current} to ${target}`
      });
    }

    const q = await client.query(
      `UPDATE orders
       SET status = $1
       ${target === 'delivered' ? ', delivered_at = NOW()' : ''}
       WHERE id = $2
         AND delivery_partner_id = $3
       RETURNING id, status`,
      [target, req.params.id, req.user.id]
    );

    if (target === 'delivered') {
      await client.query(
        `INSERT INTO delivery_transactions
           (user_id, order_id, amount, type, description, eligible_at)
         VALUES
           ($1, $2, 20, 'delivery_earning',
            'Delivery completed; withdrawal available after 7 days',
            NOW() + INTERVAL '7 days')
         ON CONFLICT (order_id, type) DO NOTHING`,
        [req.user.id, req.params.id]
      );
    }

    await client.query('COMMIT');

    await sendPushToUser(
      old.rows[0].customer_id,
      'NearKart',
      target === 'delivered'
        ? 'Your order was delivered'
        : `Your order status is now ${requested}`,
      { orderId: req.params.id, status: target },
      'order_status'
    );

    res.json({
      id: q.rows[0].id,
      status: requested
    });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

// ------------------------------------------------------------
// DELIVERY GPS - SINGLE CORRECTED ENDPOINT
// ------------------------------------------------------------

app.post('/api/delivery/location', auth, deliveryOnly, async (req, res) => {
  const lat = Number(req.body.latitude);
  const lng = Number(req.body.longitude);
  const orderId = req.body.orderId || null;

  if (
    !Number.isFinite(lat) ||
    !Number.isFinite(lng) ||
    Math.abs(lat) > 90 ||
    Math.abs(lng) > 180
  ) {
    return res.status(400).json({
      error: 'Valid latitude and longitude required'
    });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    if (orderId) {
      const own = await client.query(
        `SELECT id
         FROM orders
         WHERE id = $1
           AND delivery_partner_id = $2
           AND status IN ('assigned','picked_up','out_for_delivery')`,
        [orderId, req.user.id]
      );

      if (!own.rowCount) {
        await client.query('ROLLBACK');
        return res.status(403).json({
          error: 'Order not assigned to this delivery partner'
        });
      }
    }

    await client.query(
      `UPDATE delivery_partners
       SET current_latitude = $1,
           current_longitude = $2,
           last_location_at = NOW(),
           updated_at = NOW()
       WHERE user_id = $3`,
      [lat, lng, req.user.id]
    );

    await client.query(
      `INSERT INTO delivery_locations
         (order_id, delivery_partner_id, latitude, longitude, accuracy)
       VALUES ($1, $2, $3, $4, $5)`,
      [
        orderId,
        req.user.id,
        lat,
        lng,
        req.body.accuracy == null
          ? null
          : Number(req.body.accuracy)
      ]
    );

    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

// ------------------------------------------------------------
// DELIVERY EARNINGS
// ------------------------------------------------------------

app.get('/api/delivery/earnings', auth, deliveryOnly, async (req, res) => {
  try {
    const balance = await pool.query(
      `SELECT
         COALESCE(SUM(amount), 0) AS balance,
         COALESCE(
           SUM(amount) FILTER (
             WHERE amount > 0 AND eligible_at <= NOW()
           ), 0
         ) AS available
       FROM delivery_transactions
       WHERE user_id = $1`,
      [req.user.id]
    );

    const history = await pool.query(
      `SELECT id, order_id, amount, type, description,
              created_at, eligible_at
       FROM delivery_transactions
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT 100`,
      [req.user.id]
    );

    const withdrawals = await pool.query(
      `SELECT id, amount, status, created_at
       FROM delivery_withdrawal_requests
       WHERE user_id = $1
       ORDER BY created_at DESC
       LIMIT 30`,
      [req.user.id]
    );

    const pending = await pool.query(
      `SELECT COALESCE(SUM(amount), 0) AS amount
       FROM delivery_withdrawal_requests
       WHERE user_id = $1
         AND status IN ('pending', 'approved')`,
      [req.user.id]
    );

    res.json({
      balance: Number(balance.rows[0].balance),
      available: Math.max(
        0,
        Number(balance.rows[0].available) -
        Number(pending.rows[0].amount)
      ),
      history: history.rows,
      withdrawals: withdrawals.rows
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ------------------------------------------------------------
// WITHDRAWAL REQUEST
// ------------------------------------------------------------

app.post('/api/delivery/withdrawals', auth, deliveryOnly, async (req, res) => {
  const {
    amount,
    bankName,
    accountHolder,
    accountNumber,
    ifsc
  } = req.body;

  const n = Number(amount);

  if (
    !Number.isFinite(n) || n <= 0 ||
    !bankName || !accountHolder ||
    !accountNumber || !ifsc
  ) {
    return res.status(400).json({
      error: 'Amount and bank details are required'
    });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const earned = await client.query(
      `SELECT COALESCE(SUM(amount), 0) AS amount
       FROM delivery_transactions
       WHERE user_id = $1
         AND amount > 0
         AND eligible_at <= NOW()`,
      [req.user.id]
    );

    const requested = await client.query(
      `SELECT COALESCE(SUM(amount), 0) AS amount
       FROM delivery_withdrawal_requests
       WHERE user_id = $1
         AND status IN ('pending', 'approved')`,
      [req.user.id]
    );

    const available =
      Number(earned.rows[0].amount) -
      Number(requested.rows[0].amount);

    if (n > available) {
      await client.query('ROLLBACK');
      return res.status(400).json({
        error: `Insufficient available balance: ₹${Math.max(0, available).toFixed(2)}`
      });
    }

    const q = await client.query(
      `INSERT INTO delivery_withdrawal_requests
         (user_id, amount, bank_name, account_holder, account_number, ifsc)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING id, amount, status, created_at`,
      [
        req.user.id,
        n,
        bankName,
        accountHolder,
        accountNumber,
        String(ifsc).trim().toUpperCase()
      ]
    );

    await client.query('COMMIT');

    res.status(201).json({
      message: 'Withdrawal request sent to Admin for review',
      request: q.rows[0]
    });
  } catch (e) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: e.message });
  } finally {
    client.release();
  }
});

// ------------------------------------------------------------
// UPDATE DELIVERY DOCUMENTS
// ------------------------------------------------------------

app.post('/api/delivery/documents', auth, deliveryOnly, async (req, res) => {
  const map = {
    profileImage: 'profile_image',
    licenseImage: 'license_image',
    rcImage: 'rc_image',
    insuranceImage: 'insurance_image',
    bikeImage: 'bike_image',
    videoUrl: 'video_url',
    bikeNumber: 'bike_number',
    bikeModel: 'bike_model',
    licenseNumber: 'license_number'
  };

  try {
    const sets = [];
    const values = [];

    for (const [key, column] of Object.entries(map)) {
      if (req.body[key] !== undefined) {
        values.push(
          req.body[key] == null ? null : String(req.body[key]).trim()
        );
        sets.push(`${column} = $${values.length}`);
      }
    }

    if (!sets.length) {
      return res.status(400).json({
        error: 'Provide at least one document URL or bike detail'
      });
    }

    values.push(req.user.id);

    const q = await pool.query(
      `UPDATE delivery_partners
       SET ${sets.join(', ')},
           updated_at = NOW()
       WHERE user_id = $${values.length}
       RETURNING user_id`,
      values
    );

    if (!q.rowCount) {
      return res.status(404).json({
        error: 'Delivery profile not found'
      });
    }

    res.json({
      message: 'Delivery profile updated successfully'
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ------------------------------------------------------------
// START SERVER AFTER DATABASE SCHEMA INITIALIZATION
// ------------------------------------------------------------


app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    message: "NearKart backend is running"
  });
});

app.get("/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");

    res.status(200).json({
      success: true,
      message: "Backend and database are connected"
    });
  } catch (error) {
    console.error("Health check failed:", error.message);

    res.status(500).json({
      success: false,
      message: "Database connection failed"
    });
  }
});

ensureDeliverySchema()
  .then(async () => {
    await pool.query("SELECT 1");

    app.listen(PORT, () => {
      console.log(
        `NearKart shared backend running on port ${PORT}`
      );
    });
  })
  .catch((e) => {
    console.error(
      "Database schema initialization failed:",
      e.message
    );
    process.exit(1);
  });



