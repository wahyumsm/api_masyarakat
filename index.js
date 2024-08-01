require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const client = require("./koneksi");
const swaggerJsDoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const secretKey = process.env.SECRET_KEY || "your_secret_key";

// Konfigurasi Swagger
const swaggerOptions = {
  swaggerDefinition: {
    openapi: "3.0.0",
    info: {
      title: "API Documentation",
      version: "1.0.0",
      description: "API Documentation for the application",
    },
    servers: [
      {
        url: "http://localhost:5000",
      },
    ],
  },
  apis: ["./index.js"], // Lokasi file dokumentasi API Anda
};

const swaggerDocs = swaggerJsDoc(swaggerOptions);
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerDocs));

// Middleware autentikasi
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null)
    return res
      .status(401)
      .json({ message: "Akses ditolak karena token tidak ada" });

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.status(403).json({ message: "Token tidak Bener" });
    req.user = user;
    next();
  });
}

/**
 * @swagger
 * /loginuser:
 *   post:
 *     summary: Login user
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       200:
 *         description: Login sukses
 *       401:
 *         description: Username atau password salah
 *       500:
 *         description: Internal server error
 */
app.post("/loginuser", async (req, res) => {
  const { username, password } = req.body;
  try {
    const query = "SELECT * FROM users WHERE username = $1";
    const result = await client.query(query, [username]);

    if (result.rows.length === 0) {
      return res
        .status(401)
        .json({ success: false, message: "Username atau password salah" });
    }

    const user = result.rows[0];
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res
        .status(401)
        .json({ success: false, message: "Username atau password salah" });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username },
      secretKey,
      {
        expiresIn: "1h",
      }
    );

    res.status(200).json({
      success: true,
      token,
      username: user.username,
      fullName: user.full_name, // Assuming this field exists
      profilePicture: user.profile_picture_url, // Assuming this field exists
    });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ success: false, message: "Internal Server Error" });
  }
});

/**
 * @swagger
 * /register:
 *   post:
 *     summary: Register akun
 *     tags: [Auth]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *               full_name:
 *                 type: string
 *               profile_picture_url:
 *                 type: string
 *     responses:
 *       201:
 *         description: User berhasil didaftarkan
 *       500:
 *         description: Internal server error
 */
app.post("/register", async (req, res) => {
  const { username, password, full_name, profile_picture_url } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const query =
      "INSERT INTO users (username, password, full_name, profile_picture_url) VALUES ($1, $2, $3, $4)";
    await client.query(query, [
      username,
      hashedPassword,
      full_name,
      profile_picture_url,
    ]);
    res.status(201).json({ message: "User berhasil didaftarkan" });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Definisikan endpoint lainnya sesuai dengan format Swagger di atas...

app.listen(port, () => {
  console.log(`Server berjalan di http://localhost:${port}`);
});
