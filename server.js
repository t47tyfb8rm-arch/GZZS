const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, "data");
const DB_FILE = path.join(DATA_DIR, "db.json");
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const COOKIE_NAME = "bj_session";

function now() {
  return new Date().toISOString();
}

function id(prefix) {
  return `${prefix}_${crypto.randomBytes(12).toString("hex")}`;
}

function ensureDb() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({ users: [], reports: [], archives: [] }, null, 2));
  }
  const db = readDb();
  const adminUser = process.env.ADMIN_USER || "admin";
  const adminPassword = process.env.ADMIN_PASSWORD || "admin123456";
  if (!db.users.some((u) => u.username === adminUser)) {
    db.users.push(createUser(adminUser, adminPassword, "admin"));
  }
  String(process.env.APP_USERS || "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .forEach((pair) => {
      const idx = pair.indexOf(":");
      if (idx <= 0) return;
      const username = pair.slice(0, idx).trim();
      const password = pair.slice(idx + 1).trim();
      if (username && password && !db.users.some((u) => u.username === username)) {
        db.users.push(createUser(username, password, "user"));
      }
    });
  writeDb(db);
}

function readDb() {
  return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}

function writeDb(db) {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
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
    active: true,
    createdAt: now(),
    updatedAt: now()
  };
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

function getUser(req, db) {
  const token = parseCookies(req)[COOKIE_NAME];
  if (!token) return null;
  const [payload, sig] = token.split(".");
  if (!payload || !sig || sign(payload) !== sig) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
    const maxAgeMs = 7 * 24 * 60 * 60 * 1000;
    if (!data.uid || Date.now() - Number(data.ts || 0) > maxAgeMs) return null;
    const user = db.users.find((u) => u.id === data.uid && u.active);
    return user || null;
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

function safeReport(report, db) {
  const owner = db.users.find((u) => u.id === report.ownerId);
  return {
    id: report.id,
    name: report.name,
    date: report.date || "",
    ownerId: report.ownerId,
    owner: owner ? owner.username : "unknown",
    data: report.data || null,
    updatedAt: report.updatedAt
  };
}

function serveStatic(req, res) {
  const urlPath = decodeURIComponent(new URL(req.url, `http://${req.headers.host}`).pathname);
  let filePath = urlPath === "/" ? path.join(ROOT, "伯俊周会.html") : path.join(ROOT, urlPath);
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
  const db = readDb();
  const url = new URL(req.url, `http://${req.headers.host}`);
  const parts = url.pathname.split("/").filter(Boolean);

  if (req.method === "POST" && url.pathname === "/api/login") {
    const body = await readBody(req);
    const user = db.users.find((u) => u.username === String(body.username || "").trim() && u.active);
    if (!user || !verifyPassword(body.password || "", user.passwordHash)) return send(res, 401, { error: "用户名或密码错误" });
    return send(res, 200, { user: publicUser(user) }, {
      "Set-Cookie": `${COOKIE_NAME}=${encodeURIComponent(makeSession(user))}; HttpOnly; SameSite=Lax; Path=/; Max-Age=604800`
    });
  }

  if (req.method === "POST" && url.pathname === "/api/logout") {
    return send(res, 200, { ok: true }, { "Set-Cookie": `${COOKIE_NAME}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0` });
  }

  const user = getUser(req, db);
  if (!user) return send(res, 401, { error: "未登录" });

  if (req.method === "GET" && url.pathname === "/api/me") return send(res, 200, { user: publicUser(user) });

  if (req.method === "GET" && url.pathname === "/api/reports") {
    const reports = db.reports.filter((r) => canAccess(user, r.ownerId)).map((r) => safeReport(r, db));
    return send(res, 200, { reports });
  }

  if (req.method === "POST" && url.pathname === "/api/reports") {
    const body = await readBody(req);
    const reportId = body.id || null;
    let report = reportId ? db.reports.find((r) => r.id === reportId && canAccess(user, r.ownerId)) : null;
    if (!report) {
      report = {
        id: id("rpt"),
        ownerId: user.id,
        name: String(body.name || "未命名.md"),
        date: body.date || "",
        data: {},
        createdAt: now(),
        updatedAt: now()
      };
      db.reports.push(report);
    }
    report.name = String(body.name || report.name);
    report.date = body.date || "";
    report.data = body.data || {};
    report.updatedAt = now();
    writeDb(db);
    return send(res, 200, { report: safeReport(report, db) });
  }

  if (parts[0] === "api" && parts[1] === "reports" && parts[2]) {
    const report = db.reports.find((r) => r.id === parts[2]);
    if (!report || !canAccess(user, report.ownerId)) return send(res, 404, { error: "未找到周报" });
    if (req.method === "DELETE") {
      db.reports = db.reports.filter((r) => r.id !== report.id);
      writeDb(db);
      return send(res, 200, { ok: true });
    }
    if (req.method === "POST" && parts[3] === "rename") {
      const body = await readBody(req);
      report.name = String(body.name || report.name);
      report.updatedAt = now();
      writeDb(db);
      return send(res, 200, { report: safeReport(report, db) });
    }
  }

  if (req.method === "GET" && url.pathname === "/api/archives") {
    const archives = db.archives.filter((a) => canAccess(user, a.ownerId));
    return send(res, 200, { archives });
  }

  if (req.method === "POST" && url.pathname === "/api/archives") {
    const body = await readBody(req);
    const archive = {
      id: id("arc"),
      ownerId: user.id,
      owner: user.username,
      name: String(body.name || "未命名存档"),
      data: body.data || "{}",
      time: body.time || new Date().toLocaleString("zh-CN"),
      originalFile: body.originalFile || "",
      createdAt: now()
    };
    db.archives.push(archive);
    writeDb(db);
    return send(res, 200, { archive });
  }

  if (parts[0] === "api" && parts[1] === "archives" && parts[2] && req.method === "DELETE") {
    const archive = db.archives.find((a) => a.id === parts[2]);
    if (!archive || !canAccess(user, archive.ownerId)) return send(res, 404, { error: "未找到存档" });
    db.archives = db.archives.filter((a) => a.id !== archive.id);
    writeDb(db);
    return send(res, 200, { ok: true });
  }

  if (parts[0] === "api" && parts[1] === "users") {
    if (user.role !== "admin") return send(res, 403, { error: "需要管理员权限" });
    if (req.method === "GET") return send(res, 200, { users: db.users.map(publicUser) });
    if (req.method === "POST") {
      const body = await readBody(req);
      const username = String(body.username || "").trim();
      const password = String(body.password || "");
      if (!username || !password) return send(res, 400, { error: "用户名和密码不能为空" });
      if (db.users.some((u) => u.username === username)) return send(res, 409, { error: "用户名已存在" });
      const created = createUser(username, password, body.role === "admin" ? "admin" : "user");
      db.users.push(created);
      writeDb(db);
      return send(res, 200, { user: publicUser(created) });
    }
    if (parts[2] && req.method === "PATCH") {
      const body = await readBody(req);
      const target = db.users.find((u) => u.id === parts[2]);
      if (!target) return send(res, 404, { error: "用户不存在" });
      if (body.password) target.passwordHash = hashPassword(body.password);
      if (body.role && target.id !== user.id) target.role = body.role === "admin" ? "admin" : "user";
      if (typeof body.active === "boolean" && target.id !== user.id) target.active = body.active;
      target.updatedAt = now();
      writeDb(db);
      return send(res, 200, { user: publicUser(target) });
    }
    if (parts[2] && req.method === "DELETE") {
      if (parts[2] === user.id) return send(res, 400, { error: "不能删除当前登录管理员" });
      db.users = db.users.filter((u) => u.id !== parts[2]);
      writeDb(db);
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
});
