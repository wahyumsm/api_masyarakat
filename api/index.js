require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const client = require("../koneksi");

const app = express();
const port = process.env.PORT || 5000;

app.use(cors());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const secretKey = process.env.SECRET_KEY || "your_secret_key";

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

// Untuk login
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

// Untuk register akun
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

app.get("/userdetails", authenticateToken, async (req, res) => {
  try {
    const query =
      "SELECT username, full_name, profile_picture_url FROM users WHERE id = $1";
    const result = await client.query(query, [req.user.id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "User not found" });
    }

    const user = result.rows[0];
    res.status(200).json({
      username: user.username,
      fullName: user.full_name,
      profilePicture: user.profile_picture_url,
    });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Ambil data siswa
app.get("/api_siswa", authenticateToken, (req, res) => {
  client.query("SELECT * FROM api_siswa", (err, result) => {
    if (err) {
      console.error("Error executing query:", err);
      res.status(500).json({ message: "Internal Server Error" });
    } else {
      res.status(200).json(result.rows);
    }
  });
});

app.post("/api_siswa", authenticateToken, async (req, res) => {
  try {
    const { nama, alamat, status } = req.body;
    const query =
      "INSERT INTO api_siswa (nama, alamat, status) VALUES ($1, $2, $3)";
    await client.query(query, [nama, alamat, status]);
    res.status(201).json({ message: "Data berhasil ditambahkan" });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.put("/api_siswa/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { nama, alamat, status } = req.body;
    const query =
      "UPDATE api_siswa SET nama = $1, alamat = $2, status = $3 WHERE id = $4";
    await client.query(query, [nama, alamat, status, id]);
    res.status(200).json({ message: "Data berhasil diupdate" });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.delete("/api_siswa/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const query = "DELETE FROM api_siswa WHERE id = $1";
    await client.query(query, [id]);
    res.status(200).json({ message: "Data berhasil dihapus" });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Ambil data produk aplikasi klik belanja
app.get("/dataproduk", authenticateToken, (req, res) => {
  client.query("SELECT * FROM dataproduk", (err, result) => {
    if (err) {
      console.error("Error executing query:", err);
      res.status(500).json({ message: "Internal Server Error" });
    } else {
      res.status(200).json(result.rows);
    }
  });
});

app.post("/dataproduk", async (req, res) => {
  try {
    const { namaproduk, kategori, harga, stok, status } = req.body;
    const query =
      "INSERT INTO dataproduk (namaproduk, kategori, harga, stok, status) VALUES ($1, $2, $3, $4, $5)";
    await client.query(query, [namaproduk, kategori, harga, stok, status]);
    res.status(201).json({ message: "Data berhasil ditambahkan" });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.delete("/dataproduk/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const query = "DELETE FROM dataproduk WHERE id = $1";
    await client.query(query, [id]);
    res.status(200).json({ message: "Data berhasil dihapus" });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.put("/dataproduk/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { namaproduk, kategori, harga, stok, status } = req.body;

    const query = `
      UPDATE dataproduk
      SET namaproduk = $1, kategori = $2, harga = $3, stok = $4, status = $5
      WHERE id = $6
    `;
    await client.query(query, [namaproduk, kategori, harga, stok, status, id]);

    res.status(200).json({ message: "Data berhasil diupdate" });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.get("/dataproduk/:id", authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const query = "SELECT * FROM dataproduk WHERE id = $1";
    const result = await client.query(query, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ message: "Produk tidak ditemukan" });
    }

    res.status(200).json(result.rows[0]);
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// API untuk pagination
app.get("/dataproduk", authenticateToken, async (req, res) => {
  const { page = 1, limit = 5 } = req.query;
  const parsedPage = parseInt(page, 10);
  const parsedLimit = parseInt(limit, 10);

  const offset = (parsedPage - 1) * parsedLimit;

  try {
    const query = "SELECT * FROM dataproduk LIMIT $1 OFFSET $2";
    const result = await client.query(query, [parsedLimit, offset]);

    const countQuery = "SELECT COUNT(*) FROM dataproduk";
    const countResult = await client.query(countQuery);
    const totalCount = parseInt(countResult.rows[0].count, 10);

    res.status(200).json({ items: result.rows, totalCount });
  } catch (error) {
    console.error("Error:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

app.listen(port, () => {
  console.log(`Server berjalan di http://localhost:${port}`);
});
