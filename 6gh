require("dotenv").config();

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 10000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;

if (!DATABASE_URL) {
  console.error("ERROR: DATABASE_URL is missing.");
  process.exit(1);
}

if (!JWT_SECRET) {
  console.error("ERROR: JWT_SECRET is missing.");
  process.exit(1);
}

/* =========================
   DATABASE
========================= */

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false
});

async function db(query, params = []) {
  return pool.query(query, params);
}

/* =========================
   MIDDLEWARE
========================= */

app.use(cors());
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

/* =========================
   DATABASE INITIALIZATION
========================= */

async function initializeDatabase() {
  await db(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(100) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      full_name VARCHAR(200) DEFAULT '',
      role VARCHAR(50) NOT NULL DEFAULT 'user',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS courses (
      id SERIAL PRIMARY KEY,
      title VARCHAR(200) NOT NULL,
      description TEXT DEFAULT '',
      instructor VARCHAR(200) DEFAULT '',
      start_date DATE,
      end_date DATE,
      status VARCHAR(50) DEFAULT 'active',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS students (
      id SERIAL PRIMARY KEY,
      full_name VARCHAR(200) NOT NULL,
      phone VARCHAR(50) DEFAULT '',
      email VARCHAR(200) DEFAULT '',
      course_id INTEGER REFERENCES courses(id) ON DELETE SET NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  await db(`
    CREATE TABLE IF NOT EXISTS certificates (
      id SERIAL PRIMARY KEY,
      certificate_no VARCHAR(100) UNIQUE NOT NULL,
      student_name VARCHAR(200) NOT NULL,
      course_name VARCHAR(200) NOT NULL,
      issue_date DATE DEFAULT CURRENT_DATE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);

  /* Create first administrator if environment variables exist */
  if (process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) {
    const username = process.env.ADMIN_USERNAME.trim();

    const existing = await db(
      "SELECT id FROM users WHERE username = $1",
      [username]
    );

    if (existing.rows.length === 0) {
      const passwordHash = await bcrypt.hash(
        process.env.ADMIN_PASSWORD,
        10
      );

      await db(
        `INSERT INTO users
        (username, password_hash, full_name, role)
        VALUES ($1, $2, $3, 'admin')`,
        [
          username,
          passwordHash,
          process.env.ADMIN_FULL_NAME || "ZENOVA Administrator"
        ]
      );

      console.log("Initial administrator created.");
    }
  }

  console.log("Database initialized successfully.");
}

/* =========================
   JWT
========================= */

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username,
      role: user.role
    },
    JWT_SECRET,
    {
      expiresIn: process.env.JWT_EXPIRES || "7d"
    }
  );
}

/* =========================
   AUTHENTICATION
========================= */

function authRequired(req, res, next) {
  const authorization = req.headers.authorization || "";

  if (!authorization.startsWith("Bearer ")) {
    return res.status(401).json({
      error: "غير مصرح بالدخول"
    });
  }

  const token = authorization.substring(7);

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({
      error: "جلسة الدخول غير صالحة أو منتهية"
    });
  }
}

function adminOnly(req, res, next) {
  if (!req.user || req.user.role !== "admin") {
    return res.status(403).json({
      error: "هذه العملية متاحة للمدير فقط"
    });
  }

  next();
}

/* =========================
   HEALTH CHECK
========================= */

app.get("/api/health", async (req, res) => {
  try {
    await db("SELECT 1");

    res.json({
      success: true,
      service: "ZENOVA Center Management System",
      database: "connected",
      status: "healthy"
    });
  } catch (error) {
    console.error("Health check error:", error);

    res.status(500).json({
      success: false,
      service: "ZENOVA Center Management System",
      database: "error",
      status: "unhealthy"
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({
        error: "اسم المستخدم وكلمة المرور مطلوبان"
      });
    }

    const result = await db(
      `SELECT
        id,
        username,
        password_hash,
        full_name,
        role
       FROM users
       WHERE username = $1`,
      [username.trim()]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "اسم المستخدم أو كلمة المرور غير صحيحة"
      });
    }

    const user = result.rows[0];

    const passwordCorrect = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordCorrect) {
      return res.status(401).json({
        error: "اسم المستخدم أو كلمة المرور غير صحيحة"
      });
    }

    const token = createToken(user);

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        username: user.username,
        fullName: user.full_name,
        role: user.role
      }
    });
  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      error: "حدث خطأ في الخادم"
    });
  }
});

/* =========================
   CURRENT USER
========================= */

app.get("/api/auth/me", authRequired, async (req, res) => {
  try {
    const result = await db(
      `SELECT
        id,
        username,
        full_name,
        role
       FROM users
       WHERE id = $1`,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({
        error: "المستخدم غير موجود"
      });
    }

    const user = result.rows[0];

    res.json({
      id: user.id,
      username: user.username,
      fullName: user.full_name,
      role: user.role
    });
  } catch (error) {
    console.error("User error:", error);

    res.status(500).json({
      error: "حدث خطأ في الخادم"
    });
  }
});

/* =========================
   CHANGE PASSWORD
========================= */

app.post(
  "/api/auth/change-password",
  authRequired,
  async (req, res) => {
    try {
      const { oldPassword, newPassword } = req.body || {};

      if (!oldPassword || !newPassword) {
        return res.status(400).json({
          error: "يرجى إدخال كلمة المرور القديمة والجديدة"
        });
      }

      if (newPassword.length < 6) {
        return res.status(400).json({
          error: "كلمة المرور الجديدة يجب أن تكون 6 أحرف على الأقل"
        });
      }

      const result = await db(
        "SELECT password_hash FROM users WHERE id = $1",
        [req.user.id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({
          error: "المستخدم غير موجود"
        });
      }

      const correct = await bcrypt.compare(
        oldPassword,
        result.rows[0].password_hash
      );

      if (!correct) {
        return res.status(401).json({
          error: "كلمة المرور القديمة غير صحيحة"
        });
      }

      const passwordHash = await bcrypt.hash(
        newPassword,
        10
      );

      await db(
        "UPDATE users SET password_hash = $1 WHERE id = $2",
        [passwordHash, req.user.id]
      );

      res.json({
        success: true,
        message: "تم تغيير كلمة المرور بنجاح"
      });
    } catch (error) {
      console.error("Password error:", error);

      res.status(500).json({
        error: "حدث خطأ في الخادم"
      });
    }
  }
);

/* =========================
   CREATE USER
========================= */

app.post(
  "/api/auth/register",
  authRequired,
  adminOnly,
  async (req, res) => {
    try {
      const {
        username,
        password,
        fullName = "",
        role = "user"
      } = req.body || {};

      if (!username || !password) {
        return res.status(400).json({
          error: "اسم المستخدم وكلمة المرور مطلوبان"
        });
      }

      if (password.length < 6) {
        return res.status(400).json({
          error: "كلمة المرور يجب أن تكون 6 أحرف على الأقل"
        });
      }

      const passwordHash = await bcrypt.hash(
        password,
        10
      );

      const result = await db(
        `INSERT INTO users
        (username, password_hash, full_name, role)
        VALUES ($1, $2, $3, $4)
        RETURNING id, username, full_name, role`,
        [
          username.trim(),
          passwordHash,
          fullName,
          role
        ]
      );

      res.status(201).json({
        success: true,
        user: result.rows[0]
      });
    } catch (error) {
      console.error("Register error:", error);

      if (error.code === "23505") {
        return res.status(400).json({
          error: "اسم المستخدم مستخدم مسبقًا"
        });
      }

      res.status(500).json({
        error: "حدث خطأ في الخادم"
      });
    }
  }
);

/* =========================
   COURSES
========================= */

app.get("/api/courses", authRequired, async (req, res) => {
  try {
    const result = await db(
      `SELECT *
       FROM courses
       ORDER BY created_at DESC`
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Courses error:", error);

    res.status(500).json({
      error: "تعذر جلب الدورات"
    });
  }
});

app.post(
  "/api/courses",
  authRequired,
  adminOnly,
  async (req, res) => {
    try {
      const {
        title,
        description = "",
        instructor = "",
        startDate = null,
        endDate = null,
        status = "active"
      } = req.body || {};

      if (!title) {
        return res.status(400).json({
          error: "اسم الدورة مطلوب"
        });
      }

      const result = await db(
        `INSERT INTO courses
        (title, description, instructor,
         start_date, end_date, status)
        VALUES ($1, $2, $3, $4, $5, $6)
        RETURNING *`,
        [
          title,
          description,
          instructor,
          startDate,
          endDate,
          status
        ]
      );

      res.status(201).json({
        success: true,
        course: result.rows[0]
      });
    } catch (error) {
      console.error("Create course error:", error);

      res.status(500).json({
        error: "تعذر إنشاء الدورة"
      });
    }
  }
);

/* =========================
   STUDENTS
========================= */

app.get("/api/students", authRequired, async (req, res) => {
  try {
    const result = await db(`
      SELECT
        s.*,
        c.title AS course_title
      FROM students s
      LEFT JOIN courses c
        ON c.id = s.course_id
      ORDER BY s.created_at DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error("Students error:", error);

    res.status(500).json({
      error: "تعذر جلب المتدربين"
    });
  }
});

app.post("/api/students", authRequired, async (req, res) => {
  try {
    const {
      fullName,
      phone = "",
      email = "",
      courseId = null
    } = req.body || {};

    if (!fullName) {
      return res.status(400).json({
        error: "اسم المتدرب مطلوب"
      });
    }

    const result = await db(
      `INSERT INTO students
      (full_name, phone, email, course_id)
      VALUES ($1, $2, $3, $4)
      RETURNING *`,
      [
        fullName,
        phone,
        email,
        courseId
      ]
    );

    res.status(201).json({
      success: true,
      student: result.rows[0]
    });
  } catch (error) {
    console.error("Create student error:", error);

    res.status(500).json({
      error: "تعذر إضافة المتدرب"
    });
  }
});

/* =========================
   CERTIFICATES
========================= */

app.get(
  "/api/certificates",
  authRequired,
  async (req, res) => {
    try {
      const result = await db(
        `SELECT *
         FROM certificates
         ORDER BY created_at DESC`
      );

      res.json(result.rows);
    } catch (error) {
      console.error("Certificates error:", error);

      res.status(500).json({
        error: "تعذر جلب الشهادات"
      });
    }
  }
);

app.post(
  "/api/certificates",
  authRequired,
  async (req, res) => {
    try {
      const {
        certificateNo,
        studentName,
        courseName,
        issueDate = null
      } = req.body || {};

      if (
        !certificateNo ||
        !studentName ||
        !courseName
      ) {
        return res.status(400).json({
          error:
            "رقم الشهادة واسم المتدرب واسم الدورة مطلوبة"
        });
      }

      const result = await db(
        `INSERT INTO certificates
        (certificate_no, student_name,
         course_name, issue_date)
        VALUES
        ($1, $2, $3,
         COALESCE($4, CURRENT_DATE))
        RETURNING *`,
        [
          certificateNo,
          studentName,
          courseName,
          issueDate
        ]
      );

      res.status(201).json({
        success: true,
        certificate: result.rows[0]
      });
    } catch (error) {
      console.error(
        "Create certificate error:",
        error
      );

      if (error.code === "23505") {
        return res.status(400).json({
          error: "رقم الشهادة مستخدم مسبقًا"
        });
      }

      res.status(500).json({
        error: "تعذر إنشاء الشهادة"
      });
    }
  }
);

/* =========================
   FRONTEND
========================= */

const publicDirectory = path.join(
  __dirname,
  "public"
);

app.use(
  express.static(publicDirectory)
);

app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api/")) {
    return next();
  }

  res.sendFile(
    path.join(publicDirectory, "index.html"),
    (error) => {
      if (error) {
        res.status(404).send(
          "ZENOVA server is running, but index.html was not found."
        );
      }
    }
  );
});

/* =========================
   ERROR HANDLER
========================= */

app.use((error, req, res, next) => {
  console.error("Unhandled error:", error);

  res.status(500).json({
    error: "حدث خطأ غير متوقع في الخادم"
  });
});

/* =========================
   START SERVER
========================= */

async function startServer() {
  try {
    await initializeDatabase();

    await db("SELECT 1");

    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          `ZENOVA server running on port ${PORT}`
        );
      }
    );
  } catch (error) {
    console.error(
      "Failed to start ZENOVA:",
      error
    );

    process.exit(1);
  }
}

/* =========================
   SAFE SHUTDOWN
========================= */

process.on("SIGTERM", async () => {
  console.log("Shutting down...");

  await pool.end();

  process.exit(0);
});

process.on("SIGINT", async () => {
  console.log("Shutting down...");

  await pool.end();

  process.exit(0);
});

startServer();
