const express = require("express");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const mysql = require("mysql");
const cors = require("cors");

require("dotenv").config();

const app = express();
app.use(cors());
app.use(bodyParser.json());

const secretKey = "your_secret_key"; // JWT 시크릿 키

// MariaDB 연결 설정
const db = mysql.createConnection({
  host: "localhost",
  user: process.env.USER_NAME,
  password: process.env.PASSWORD,
  database: "memodb",
});

db.connect((err) => {
  if (err) throw err;
  console.log("Connected to memodb");
});

// JWT 인증 미들웨어
const authenticateJWT = (req, res, next) => {
  const token = req.header("Authorization")?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Access denied" });

  jwt.verify(token, secretKey, (err, user) => {
    if (err) return res.status(403).json({ message: "Invalid token" });
    req.user = user;
    next();
  });
};

// JWT 토큰 검증 엔드포인트
app.get("/verifyToken", authenticateJWT, (req, res) => {
  res.status(200).json({ message: "Token is valid" });
});

// 비밀번호 해싱 함수
const hashPassword = async (password) => {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
};

// 비밀번호 비교 함수
const comparePassword = async (password, hash) => {
  return bcrypt.compare(password, hash);
};

// 회원가입
app.post("/register", async (req, res) => {
  const { userId, userPw } = req.body;
  const hashedPw = await hashPassword(userPw);

  // 사용자 등록
  db.query(
    "INSERT INTO user (userId, userPw) VALUES (?, ?)",
    [userId, hashedPw],
    (err) => {
      if (err) {
        return res.status(500).json({ message: "User registration failed" });
      }

      // 기본 'Unknown' 카테고리 생성
      db.query(
        "INSERT INTO category (userId, categoryName) VALUES (?, ?)",
        [userId, "Unknown"],
        (categoryErr) => {
          if (categoryErr) {
            return res
              .status(500)
              .json({ message: "Failed to create default category" });
          }
          res.status(201).json({ message: "User registered successfully" });
        }
      );
    }
  );
});

// 로그인
app.post("/login", (req, res) => {
  const { userId, userPw } = req.body;

  db.query(
    "SELECT * FROM user WHERE userId = ?",
    [userId],
    async (err, results) => {
      if (err || results.length === 0) {
        return res.status(401).json({ message: "Invalid credentials" });
      }

      const user = results[0];
      const validPw = await comparePassword(userPw, user.userPw);
      if (!validPw) {
        return res.status(401).json({ message: "Invalid credentials" });
      }

      // JWT 발급
      const token = jwt.sign({ userId: user.userId }, secretKey, {
        expiresIn: "1h",
      });
      res.json({ token });
    }
  );
});

// 회원정보 수정
app.put("/user", authenticateJWT, async (req, res) => {
  const { userPw } = req.body;
  const hashedPw = await hashPassword(userPw);

  db.query(
    "UPDATE user SET userPw = ? WHERE userId = ?",
    [hashedPw, req.user.userId],
    (err) => {
      if (err)
        return res.status(500).json({ message: "Failed to update user" });
      res.json({ message: "User updated successfully" });
    }
  );
});

// 탈퇴
app.delete("/user", authenticateJWT, (req, res) => {
  const userId = req.user.userId;

  // 해당 사용자의 모든 메모 삭제
  db.query(
    "DELETE FROM memo WHERE categoryId IN (SELECT categoryId FROM category WHERE userId = ?)",
    [userId],
    (err) => {
      if (err) {
        console.log(err);
        return res.status(500).json({ message: "Failed to delete memos" });
      }

      // 메모 삭제 후 카테고리 삭제
      db.query("DELETE FROM category WHERE userId = ?", [userId], (err) => {
        if (err) {
          console.log(err);
          return res
            .status(500)
            .json({ message: "Failed to delete categories" });
        }

        // 카테고리 삭제 후 사용자 삭제
        db.query("DELETE FROM user WHERE userId = ?", [userId], (err) => {
          if (err) {
            console.log(err);
            return res.status(500).json({ message: "Failed to delete user" });
          }

          res.json({ message: "User deleted successfully" });
        });
      });
    }
  );
});

// 카테고리 목록 조회
app.get("/categories", authenticateJWT, (req, res) => {
  db.query(
    "SELECT * FROM category WHERE userId = ?",
    [req.user.userId],
    (err, results) => {
      if (err) {
        console.error("Failed to fetch categories:", err); // 로그 확인
        return res.status(500).json({ message: "Failed to fetch categories" });
      }
      res.json(results);
    }
  );
});

// 카테고리 추가
app.post("/categories", authenticateJWT, (req, res) => {
  const { categoryName } = req.body;
  db.query(
    "INSERT INTO category (userId, categoryName) VALUES (?, ?)",
    [req.user.userId, categoryName],
    (err) => {
      if (err)
        return res.status(500).json({ message: "Failed to add category" });
      res.status(201).json({ message: "Category added successfully" });
    }
  );
});

// 카테고리 삭제
app.delete("/categories/:id", authenticateJWT, (req, res) => {
  const categoryId = req.params.id;

  // 해당 카테고리의 모든 메모 삭제 후 카테고리 삭제
  db.query(
    "DELETE FROM memo WHERE categoryId = ? AND userId = ?",
    [categoryId, req.user.userId],
    (err) => {
      if (err) {
        return res.status(500).json({ message: "Failed to delete memos" });
      }

      // 카테고리 삭제
      db.query(
        "DELETE FROM category WHERE categoryId = ? AND userId = ?",
        [categoryId, req.user.userId],
        (err) => {
          if (err) {
            return res
              .status(500)
              .json({ message: "Failed to delete category" });
          }
          res.json({
            message: "Category and associated memos deleted successfully",
          });
        }
      );
    }
  );
});

// 새 메모 추가 (기본적으로 제목과 내용은 빈 상태)
app.post("/memos/new", authenticateJWT, (req, res) => {
  // 현재 유저의 'Unknown' 카테고리를 찾음
  db.query(
    "SELECT categoryId FROM category WHERE userId = ? AND categoryName = 'Unknown'",
    [req.user.userId],
    (err, result) => {
      if (err || result.length === 0) {
        return res
          .status(500)
          .json({ message: "Failed to find default category" });
      }

      const categoryId = result[0].categoryId; // Unknown 카테고리 ID 사용
      const memoTitle = ""; // 기본적으로 제목은 빈 문자열
      const memoContent = ""; // 기본적으로 내용은 빈 문자열

      db.query(
        "INSERT INTO memo (userId, categoryId, memoTitle, memoContent) VALUES (?, ?, ?, ?)",
        [req.user.userId, categoryId, memoTitle, memoContent],
        (err, result) => {
          if (err) {
            console.error("Error creating memo:", err);
            return res.status(500).json({ message: "Failed to create memo" });
          }
          const newMemoId = result.insertId;
          res.status(201).json({ memoId: newMemoId });
        }
      );
    }
  );
});

// 메모 조회
app.get("/memos/:id", authenticateJWT, (req, res) => {
  db.query(
    "SELECT * FROM memo WHERE memoId = ? AND userId = ?",
    [req.params.id, req.user.userId],
    (err, results) => {
      if (err || results.length === 0) {
        return res.status(404).json({ message: "Memo not found" });
      }
      res.json(results[0]);
    }
  );
});

// 메모 수정
app.put("/memos/:id", authenticateJWT, (req, res) => {
  const { memoTitle, memoContent, categoryId } = req.body; // categoryId도 요청에서 받아옴

  db.query(
    "UPDATE memo SET memoTitle = ?, memoContent = ?, categoryId = ? WHERE memoId = ? AND userId = ?",
    [memoTitle, memoContent, categoryId, req.params.id, req.user.userId], // categoryId 포함
    (err) => {
      if (err) {
        console.error("Failed to update memo:", err);
        return res.status(500).json({ message: "Failed to update memo" });
      }
      res.json({ message: "Memo updated successfully" });
    }
  );
});

// 메모 삭제
app.delete("/memos/:id", authenticateJWT, (req, res) => {
  db.query(
    "DELETE FROM memo WHERE memoId = ? AND userId = ?",
    [req.params.id, req.user.userId],
    (err) => {
      if (err)
        return res.status(500).json({ message: "Failed to delete memo" });
      res.json({ message: "Memo deleted successfully" });
    }
  );
});

// 메모 조회
app.get("/memos/:id", authenticateJWT, (req, res) => {
  db.query(
    "SELECT * FROM memo WHERE memoId = ? AND userId = ?",
    [req.params.id, req.user.userId],
    (err, results) => {
      if (err || results.length === 0)
        return res.status(404).json({ message: "Memo not found" });
      res.json(results[0]);
    }
  );
});

// 메모 리스트 조회 (제목과 ID만)
app.get("/memos", authenticateJWT, (req, res) => {
  db.query(
    "SELECT memoId, memoTitle FROM memo WHERE userId = ?",
    [req.user.userId],
    (err, results) => {
      if (err)
        return res.status(500).json({ message: "Failed to fetch memos" });
      res.json(results);
    }
  );
});

// 카테고리별 메모 리스트 조회
app.get("/memos/category/:categoryId", authenticateJWT, (req, res) => {
  const { categoryId } = req.params;

  db.query(
    "SELECT memoId, memoTitle FROM memo WHERE categoryId = ? AND userId = ?",
    [categoryId, req.user.userId],
    (err, results) => {
      if (err) {
        console.error("Error fetching memos:", err);
        return res.status(500).json({ message: "Failed to fetch memos" });
      }
      res.json(results);
    }
  );
});

// 서버 실행
const PORT = process.env.PORT || 8080;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
