const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const Database = require("better-sqlite3");

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const DB_FILE = path.join(DATA_DIR, "app.sqlite");
const LEGACY_JSON_FILE = path.join(DATA_DIR, "db.json");
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const COOKIE_NAME = "bj_session";

let db;

function now() {
  return new Date().toISOString();
}

function id(prefix) {
  return `${prefix}_${crypto.randomBytes(12).toString("hex")}`;
}

function ensureDb() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  db = new Database(DB_FILE);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin','user')),
      active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS reports (
      id TEXT PRIMARY KEY,
      owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      folder TEXT NOT NULL DEFAULT '默认',
      date TEXT,
      data TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_reports_owner ON reports(owner_id);
    CREATE INDEX IF NOT EXISTS idx_reports_date ON reports(date);
    CREATE INDEX IF NOT EXISTS idx_reports_folder ON reports(folder);
    CREATE TABLE IF NOT EXISTS folders (
      id TEXT PRIMARY KEY,
      owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_folders_owner ON folders(owner_id);
    CREATE TABLE IF NOT EXISTS archives (
      id TEXT PRIMARY KEY,
      owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      data TEXT NOT NULL,
      time TEXT,
      original_file TEXT,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_archives_owner ON archives(owner_id);
  `);
  ensureSchema();
  migrateLegacyJson();
  seedUsers();
}

function ensureSchema() {
  const reportColumns = db.prepare("PRAGMA table_info(reports)").all().map((col) => col.name);
  if (!reportColumns.includes("folder")) {
    db.prepare("ALTER TABLE reports ADD COLUMN folder TEXT NOT NULL DEFAULT '默认'").run();
  }
}

function migrateLegacyJson() {
  if (!fs.existsSync(LEGACY_JSON_FILE)) return;
  const existingUsers = db.prepare("SELECT COUNT(*) AS count FROM users").get().count;
  const existingReports = db.prepare("SELECT COUNT(*) AS count FROM reports").get().count;
  const existingArchives = db.prepare("SELECT COUNT(*) AS count FROM archives").get().count;
  if (existingUsers || existingReports || existingArchives) return;

  let legacy;
  try {
    legacy = JSON.parse(fs.readFileSync(LEGACY_JSON_FILE, "utf8"));
  } catch {
    return;
  }

  const insertUser = db.prepare(`
    INSERT INTO users (id, username, password_hash, role, active, created_at, updated_at)
    VALUES (@id, @username, @passwordHash, @role, @active, @createdAt, @updatedAt)
  `);
  const insertReport = db.prepare(`
    INSERT INTO reports (id, owner_id, name, folder, date, data, created_at, updated_at)
    VALUES (@id, @ownerId, @name, @folder, @date, @data, @createdAt, @updatedAt)
  `);
  const insertArchive = db.prepare(`
    INSERT INTO archives (id, owner_id, name, data, time, original_file, created_at)
    VALUES (@id, @ownerId, @name, @data, @time, @originalFile, @createdAt)
  `);

  const tx = db.transaction(() => {
    (legacy.users || []).forEach((user) => {
      insertUser.run({
        id: user.id,
        username: user.username,
        passwordHash: user.passwordHash,
        role: user.role === "admin" ? "admin" : "user",
        active: user.active === false ? 0 : 1,
        createdAt: user.createdAt || now(),
        updatedAt: user.updatedAt || now()
      });
    });
    (legacy.reports || []).forEach((report) => {
      insertReport.run({
        id: report.id,
        ownerId: report.ownerId,
        name: report.name || "未命名.md",
        folder: report.folder || "默认",
        date: report.date || "",
        data: JSON.stringify(report.data || {}),
        createdAt: report.createdAt || now(),
        updatedAt: report.updatedAt || now()
      });
    });
    (legacy.archives || []).forEach((archive) => {
      insertArchive.run({
        id: archive.id,
        ownerId: archive.ownerId,
        name: archive.name || "未命名存档",
        data: archive.data || "{}",
        time: archive.time || "",
        originalFile: archive.originalFile || "",
        createdAt: archive.createdAt || now()
      });
    });
  });
  tx();
}

function seedUsers() {
  const adminUser = process.env.ADMIN_USER || "admin";
  const adminPassword = process.env.ADMIN_PASSWORD || "admin123456";
  if (!getUserByUsername(adminUser)) insertUser(createUser(adminUser, adminPassword, "admin"));

  String(process.env.APP_USERS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .forEach((pair) => {
      const idx = pair.indexOf(":");
      if (idx <= 0) return;
      const username = pair.slice(0, idx).trim();
      const password = pair.slice(idx + 1).trim();
      if (username && password && !getUserByUsername(username)) {
        insertUser(createUser(username, password, "user"));
      }
    });
}

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.pbkdf2Sync(String(password), salt, 120000, 32, "sha256").toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = String(stored || "").split(":");
  if (!salt || !hash) return false;
  const check = hashPassword(password, salt).split(":")[1];
  return crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(check, "hex"));
}

function createUser(username, password, role = "user") {
  return {
    id: id("usr"),
    username,
    passwordHash: hashPassword(password),
    role,
    active: 1,
    createdAt: now(),
    updatedAt: now()
  };
}

function insertUser(user) {
  db.prepare(`
    INSERT INTO users (id, username, password_hash, role, active, created_at, updated_at)
    VALUES (@id, @username, @passwordHash, @role, @active, @createdAt, @updatedAt)
  `).run(user);
}

function rowToUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: row.username,
    passwordHash: row.password_hash,
    role: row.role,
    active: Boolean(row.active),
    createdAt: row.created_at,
    updatedAt: row.updated_at
  };
}

function getUserByUsername(username) {
  return rowToUser(db.prepare("SELECT * FROM users WHERE username = ?").get(username));
}

function getUserById(idValue) {
  return rowToUser(db.prepare("SELECT * FROM users WHERE id = ?").get(idValue));
}

function sign(value) {
  return crypto.createHmac("sha256", SESSION_SECRET).update(value).digest("hex");
}

function makeSession(user) {
  const payload = Buffer.from(JSON.stringify({ uid: user.id, ts: Date.now() })).toString("base64url");
  return `${payload}.${sign(payload)}`;
}

function parseCookies(req) {
  const out = {};
  String(req.headers.cookie || "").split(";").forEach((part) => {
    const idx = part.indexOf("=");
    if (idx > -1) out[part.slice(0, idx).trim()] = decodeURIComponent(part.slice(idx + 1).trim());
  });
  return out;
}

function getUser(req) {
  const token = parseCookies(req)[COOKIE_NAME];
  if (!token) return null;
  const [payload, sig] = token.split(".");
  if (!payload || !sig || sign(payload) !== sig) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    const maxAgeMs = 7 * 24 * 60 * 60 * 1000;
    if (!data.uid || Date.now() - Number(data.ts || 0) > maxAgeMs) return null;
    const user = getUserById(data.uid);
    return user && user.active ? user : null;
  } catch {
    return null;
  }
}

function send(res, status, data, headers = {}) {
  const body = data === undefined ? "" : JSON.stringify(data);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...headers
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 10 * 1024 * 1024) {
        reject(new Error("请求体过大"));
        req.destroy();
      }
    });
    req.on("end", () => {
      if (!body) return resolve({});
      try {
        resolve(JSON.parse(body));
      } catch {
        reject(new Error("JSON 格式错误"));
      }
    });
    req.on("error", reject);
  });
}

function publicUser(user) {
  return { id: user.id, username: user.username, role: user.role, active: user.active };
}

function canAccess(user, ownerId) {
  return user.role === "admin" || user.id === ownerId;
}

function parseData(value, fallback) {
  try {
    return JSON.parse(value || "");
  } catch {
    return fallback;
  }
}

function safeReport(row) {
  return {
    id: row.id,
    name: row.name,
    folder: row.folder || "默认",
    date: row.date || "",
    ownerId: row.owner_id,
    owner: row.owner || "unknown",
    data: parseData(row.data, {}),
    updatedAt: row.updated_at
  };
}

function safeFolder(row) {
  return {
    id: row.id,
    name: row.name || "默认",
    ownerId: row.owner_id,
    owner: row.owner || "unknown",
    updatedAt: row.updated_at
  };
}

function safeArchive(row) {
  return {
    id: row.id,
    ownerId: row.owner_id,
    owner: row.owner || "unknown",
    name: row.name,
    data: row.data || "{}",
    time: row.time || "",
    originalFile: row.original_file || "",
    createdAt: row.created_at
  };
}

function serveStatic(req, res) {
  const urlPath = decodeURIComponent(new URL(req.url, `http://${req.headers.host}`).pathname);
  const filePath = urlPath === "/" ? path.join(ROOT, "伯俊周会.html") : path.join(ROOT, urlPath);
  if (!filePath.startsWith(ROOT)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }
  if (!fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    res.writeHead(404);
    res.end("Not found");
    return;
  }
  const ext = path.extname(filePath).toLowerCase();
  const types = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8" };
  res.writeHead(200, { "Content-Type": types[ext] || "application/octet-stream" });
  fs.createReadStream(filePath).pipe(res);
}

async function handleApi(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const parts = url.pathname.split("/").filter(Boolean);

  if (req.method === "POST" && url.pathname === "/api/login") {
    const body = await readBody(req);
    const user = getUserByUsername(String(body.username || "").trim());
    if (!user || !user.active || !verifyPassword(body.password || "", user.passwordHash)) {
      return send(res, 401, { error: "用户名或密码错误" });
    }
    return send(res, 200, { user: publicUser(user) }, {
      "Set-Cookie": `${COOKIE_NAME}=${encodeURIComponent(makeSession(user))}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800`
    });
  }

  if (req.method === "POST" && url.pathname === "/api/logout") {
    return send(res, 200, { ok: true }, { "Set-Cookie": `${COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0` });
  }

  const user = getUser(req);
  if (!user) return send(res, 401, { error: "未登录" });

  if (req.method === "GET" && url.pathname === "/api/me") return send(res, 200, { user: publicUser(user) });

  if (req.method === "GET" && url.pathname === "/api/reports") {
    const sql = `
      SELECT reports.*, users.username AS owner
      FROM reports
      JOIN users ON users.id = reports.owner_id
      ${user.role === "admin" ? "" : "WHERE reports.owner_id = ?"}
      ORDER BY reports.updated_at DESC
    `;
    const rows = user.role === "admin" ? db.prepare(sql).all() : db.prepare(sql).all(user.id);
    const folderSql = `
      SELECT folders.*, users.username AS owner
      FROM folders
      JOIN users ON users.id = folders.owner_id
      ${user.role === "admin" ? "" : "WHERE folders.owner_id = ?"}
      ORDER BY folders.updated_at DESC
    `;
    const folderRows = user.role === "admin" ? db.prepare(folderSql).all() : db.prepare(folderSql).all(user.id);
    return send(res, 200, { reports: rows.map(safeReport), folders: folderRows.map(safeFolder) });
  }

  if (req.method === "POST" && url.pathname === "/api/folders") {
    const body = await readBody(req);
    const name = String(body.name || "默认").trim() || "默认";
    const existing = db.prepare("SELECT * FROM folders WHERE owner_id = ? AND name = ?").get(user.id, name);
    if (existing) return send(res, 200, { folder: safeFolder({ ...existing, owner: user.username }) });
    const payload = { id: id("fld"), ownerId: user.id, name, createdAt: now(), updatedAt: now() };
    db.prepare(`
      INSERT INTO folders (id, owner_id, name, created_at, updated_at)
      VALUES (@id, @ownerId, @name, @createdAt, @updatedAt)
    `).run(payload);
    const saved = db.prepare(`
      SELECT folders.*, users.username AS owner
      FROM folders JOIN users ON users.id = folders.owner_id
      WHERE folders.id = ?
    `).get(payload.id);
    return send(res, 200, { folder: safeFolder(saved) });
  }

  if (req.method === "POST" && url.pathname === "/api/reports") {
    const body = await readBody(req);
    const reportId = body.id || null;
    const report = reportId ? db.prepare("SELECT * FROM reports WHERE id = ?").get(reportId) : null;
    if (report && !canAccess(user, report.owner_id)) return send(res, 404, { error: "未找到周报" });

    const payload = {
      id: report ? report.id : id("rpt"),
      ownerId: report ? report.owner_id : user.id,
      name: String(body.name || (report && report.name) || "未命名.md"),
      folder: String(body.folder || (report && report.folder) || "默认").trim() || "默认",
      date: body.date || "",
      data: JSON.stringify(body.data || {}),
      createdAt: report ? report.created_at : now(),
      updatedAt: now()
    };

    db.prepare(`
      INSERT INTO reports (id, owner_id, name, folder, date, data, created_at, updated_at)
      VALUES (@id, @ownerId, @name, @folder, @date, @data, @createdAt, @updatedAt)
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        folder = excluded.folder,
        date = excluded.date,
        data = excluded.data,
        updated_at = excluded.updated_at
    `).run(payload);

    const saved = db.prepare(`
      SELECT reports.*, users.username AS owner
      FROM reports JOIN users ON users.id = reports.owner_id
      WHERE reports.id = ?
    `).get(payload.id);
    return send(res, 200, { report: safeReport(saved) });
  }

  if (parts[0] === "api" && parts[1] === "reports" && parts[2]) {
    const report = db.prepare("SELECT * FROM reports WHERE id = ?").get(parts[2]);
    if (!report || !canAccess(user, report.owner_id)) return send(res, 404, { error: "未找到周报" });
    if (req.method === "DELETE") {
      db.prepare("DELETE FROM reports WHERE id = ?").run(report.id);
      return send(res, 200, { ok: true });
    }
    if (req.method === "POST" && parts[3] === "rename") {
      const body = await readBody(req);
      db.prepare("UPDATE reports SET name = ?, updated_at = ? WHERE id = ?").run(String(body.name || report.name), now(), report.id);
      const renamed = db.prepare(`
        SELECT reports.*, users.username AS owner
        FROM reports JOIN users ON users.id = reports.owner_id
        WHERE reports.id = ?
      `).get(report.id);
      return send(res, 200, { report: safeReport(renamed) });
    }
    if (req.method === "POST" && parts[3] === "folder") {
      const body = await readBody(req);
      const folder = String(body.folder || "默认").trim() || "默认";
      const exists = db.prepare("SELECT * FROM folders WHERE owner_id = ? AND name = ?").get(report.owner_id, folder);
      if (!exists) {
        db.prepare(`
          INSERT INTO folders (id, owner_id, name, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?)
        `).run(id("fld"), report.owner_id, folder, now(), now());
      }
      db.prepare("UPDATE reports SET folder = ?, updated_at = ? WHERE id = ?").run(folder, now(), report.id);
      const moved = db.prepare(`
        SELECT reports.*, users.username AS owner
        FROM reports JOIN users ON users.id = reports.owner_id
        WHERE reports.id = ?
      `).get(report.id);
      return send(res, 200, { report: safeReport(moved) });
    }
  }

  if (req.method === "POST" && url.pathname === "/api/folders/rename") {
    const body = await readBody(req);
    const oldFolder = String(body.oldFolder || "默认").trim() || "默认";
    const newFolder = String(body.newFolder || "默认").trim() || "默认";
    if (!newFolder) return send(res, 400, { error: "文件夹名称不能为空" });
    const sql = user.role === "admin"
      ? "UPDATE reports SET folder = ?, updated_at = ? WHERE folder = ?"
      : "UPDATE reports SET folder = ?, updated_at = ? WHERE folder = ? AND owner_id = ?";
    const result = user.role === "admin"
      ? db.prepare(sql).run(newFolder, now(), oldFolder)
      : db.prepare(sql).run(newFolder, now(), oldFolder, user.id);
    if (user.role === "admin") {
      db.prepare("UPDATE folders SET name = ?, updated_at = ? WHERE name = ?").run(newFolder, now(), oldFolder);
    } else {
      db.prepare("UPDATE folders SET name = ?, updated_at = ? WHERE name = ? AND owner_id = ?").run(newFolder, now(), oldFolder, user.id);
    }
    return send(res, 200, { ok: true, changed: result.changes });
  }

  if (req.method === "GET" && url.pathname === "/api/archives") {
    const sql = `
      SELECT archives.*, users.username AS owner
      FROM archives
      JOIN users ON users.id = archives.owner_id
      ${user.role === "admin" ? "" : "WHERE archives.owner_id = ?"}
      ORDER BY archives.created_at DESC
    `;
    const rows = user.role === "admin" ? db.prepare(sql).all() : db.prepare(sql).all(user.id);
    return send(res, 200, { archives: rows.map(safeArchive) });
  }

  if (req.method === "POST" && url.pathname === "/api/archives") {
    const body = await readBody(req);
    const archive = {
      id: id("arc"),
      ownerId: user.id,
      name: String(body.name || "未命名存档"),
      data: body.data || "{}",
      time: body.time || new Date().toLocaleString("zh-CN"),
      originalFile: body.originalFile || "",
      createdAt: now()
    };
    db.prepare(`
      INSERT INTO archives (id, owner_id, name, data, time, original_file, created_at)
      VALUES (@id, @ownerId, @name, @data, @time, @originalFile, @createdAt)
    `).run(archive);
    return send(res, 200, { archive: { ...archive, owner: user.username, ownerId: user.id } });
  }

  if (parts[0] === "api" && parts[1] === "archives" && parts[2] && req.method === "DELETE") {
    const archive = db.prepare("SELECT * FROM archives WHERE id = ?").get(parts[2]);
    if (!archive || !canAccess(user, archive.owner_id)) return send(res, 404, { error: "未找到存档" });
    db.prepare("DELETE FROM archives WHERE id = ?").run(archive.id);
    return send(res, 200, { ok: true });
  }

  if (parts[0] === "api" && parts[1] === "users") {
    if (user.role !== "admin") return send(res, 403, { error: "需要管理员权限" });
    if (req.method === "GET") {
      const users = db.prepare("SELECT * FROM users ORDER BY created_at ASC").all().map(rowToUser).map(publicUser);
      return send(res, 200, { users });
    }
    if (req.method === "POST") {
      const body = await readBody(req);
      const username = String(body.username || "").trim();
      const password = String(body.password || "");
      if (!username || !password) return send(res, 400, { error: "用户名和密码不能为空" });
      if (getUserByUsername(username)) return send(res, 409, { error: "用户名已存在" });
      const created = createUser(username, password, body.role === "admin" ? "admin" : "user");
      insertUser(created);
      return send(res, 200, { user: publicUser(created) });
    }
    if (parts[2] && req.method === "PATCH") {
      const body = await readBody(req);
      const target = getUserById(parts[2]);
      if (!target) return send(res, 404, { error: "用户不存在" });
      const nextPasswordHash = body.password ? hashPassword(body.password) : target.passwordHash;
      const nextRole = body.role && target.id !== user.id ? (body.role === "admin" ? "admin" : "user") : target.role;
      const nextActive = typeof body.active === "boolean" && target.id !== user.id ? (body.active ? 1 : 0) : (target.active ? 1 : 0);
      db.prepare(`
        UPDATE users
        SET password_hash = ?, role = ?, active = ?, updated_at = ?
        WHERE id = ?
      `).run(nextPasswordHash, nextRole, nextActive, now(), target.id);
      return send(res, 200, { user: publicUser(getUserById(target.id)) });
    }
    if (parts[2] && req.method === "DELETE") {
      if (parts[2] === user.id) return send(res, 400, { error: "不能删除当前登录管理员" });
      db.prepare("DELETE FROM users WHERE id = ?").run(parts[2]);
      return send(res, 200, { ok: true });
    }
  }

  send(res, 404, { error: "接口不存在" });
}

ensureDb();

http.createServer((req, res) => {
  if (req.url.startsWith("/api/")) {
    handleApi(req, res).catch((err) => send(res, 500, { error: err.message || "服务器错误" }));
  } else {
    serveStatic(req, res);
  }
}).listen(PORT, () => {
  console.log(`伯俊周会已启动: http://localhost:${PORT}`);
  console.log(`SQLite 数据库: ${DB_FILE}`);
});
