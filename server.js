/* =========================================================
   进出货管理系统 - 后端服务
   运行：node server.js
   访问：http://localhost:3000
   数据保存在同目录的 data.json 中，任何浏览器登录同一账号
   都能看到相同的历史数据。
   ========================================================= */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA_FILE = path.join(ROOT, 'data.json');

let store = { users: [], data: {}, sessions: {} };

function loadStore() {
  try {
    const obj = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    store = {
      users: Array.isArray(obj.users) ? obj.users : [],
      data: obj.data && typeof obj.data === 'object' ? obj.data : {},
      sessions: obj.sessions && typeof obj.sessions === 'object' ? obj.sessions : {}
    };
  } catch (e) {
    store = { users: [], data: {}, sessions: {} };
  }
}
function saveStore() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(store, null, 2), 'utf8');
}

const uid = () => crypto.randomBytes(12).toString('hex');
const hashPwd = (pwd, salt) =>
  crypto.pbkdf2Sync(pwd, salt, 120000, 32, 'sha256').toString('hex');

function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS'
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => {
      data += c;
      if (data.length > 8e6) { reject(new Error('请求体过大')); req.destroy(); }
    });
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); }
      catch (e) { reject(new Error('JSON 格式错误')); }
    });
    req.on('error', reject);
  });
}

function authUser(req) {
  const h = req.headers['authorization'] || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  const sess = store.sessions[m[1]];
  if (!sess) return null;
  return store.users.find(u => u.id === sess.userId) || null;
}

const emptyData = () => ({
  openingCapital: 0, openingDate: '', openingRemark: '',
  suppliers: [], customers: [], records: []
});

function sanitizeData(d) {
  d = d || {};
  return {
    openingCapital: Number(d.openingCapital) || 0,
    openingDate: typeof d.openingDate === 'string' ? d.openingDate : '',
    openingRemark: typeof d.openingRemark === 'string' ? d.openingRemark : '',
    suppliers: Array.isArray(d.suppliers) ? d.suppliers : [],
    customers: Array.isArray(d.customers) ? d.customers : [],
    records: Array.isArray(d.records) ? d.records : []
  };
}

const server = http.createServer(async (req, res) => {
  let p = '/';
  try { p = new URL(req.url, 'http://localhost').pathname; } catch (e) {}

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS'
    });
    return res.end();
  }

  try {
    /* ---------- 健康检查 ---------- */
    if (p === '/api/health') {
      return send(res, 200, { ok: true, time: Date.now() });
    }

    /* ---------- 注册 ---------- */
    if (p === '/api/register' && req.method === 'POST') {
      const body = await readBody(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');
      if (!/^[A-Za-z0-9_\u4e00-\u9fa5]{3,20}$/.test(username))
        return send(res, 400, { ok: false, msg: '账号需为 3-20 位字母、数字、下划线或中文' });
      if (password.length < 6)
        return send(res, 400, { ok: false, msg: '密码至少 6 位' });
      if (store.users.some(x => x.username.toLowerCase() === username.toLowerCase()))
        return send(res, 400, { ok: false, msg: '该账号已被注册' });

      const salt = crypto.randomBytes(8).toString('hex');
      const user = { id: uid(), username, salt, hash: hashPwd(password, salt), createdAt: Date.now() };
      store.users.push(user);
      store.data[user.id] = emptyData();
      const token = crypto.randomBytes(24).toString('hex');
      store.sessions[token] = { userId: user.id, createdAt: Date.now() };
      saveStore();
      return send(res, 200, { ok: true, token, user: { id: user.id, username } });
    }

    /* ---------- 登录 ---------- */
    if (p === '/api/login' && req.method === 'POST') {
      const body = await readBody(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');
      const user = store.users.find(x => x.username.toLowerCase() === username.toLowerCase());
      if (!user) return send(res, 400, { ok: false, msg: '账号不存在，请先注册' });
      if (hashPwd(password, user.salt) !== user.hash)
        return send(res, 400, { ok: false, msg: '密码不正确' });

      const token = crypto.randomBytes(24).toString('hex');
      store.sessions[token] = { userId: user.id, createdAt: Date.now() };
      if (!store.data[user.id]) store.data[user.id] = emptyData();
      saveStore();
      return send(res, 200, { ok: true, token, user: { id: user.id, username: user.username } });
    }

    /* ---------- 当前用户 ---------- */
    if (p === '/api/me' && req.method === 'GET') {
      const user = authUser(req);
      if (!user) return send(res, 401, { ok: false, msg: '未登录或登录已过期' });
      return send(res, 200, { ok: true, user: { id: user.id, username: user.username } });
    }

    /* ---------- 退出 ---------- */
    if (p === '/api/logout' && req.method === 'POST') {
      const h = req.headers['authorization'] || '';
      const m = h.match(/^Bearer\s+(.+)$/i);
      if (m && store.sessions[m[1]]) { delete store.sessions[m[1]]; saveStore(); }
      return send(res, 200, { ok: true });
    }

    /* ---------- 读取数据 ---------- */
    if (p === '/api/data' && req.method === 'GET') {
      const user = authUser(req);
      if (!user) return send(res, 401, { ok: false, msg: '未登录或登录已过期' });
      const d = store.data[user.id] || emptyData();
      return send(res, 200, { ok: true, data: d });
    }

    /* ---------- 保存数据 ---------- */
    if (p === '/api/data' && req.method === 'PUT') {
      const user = authUser(req);
      if (!user) return send(res, 401, { ok: false, msg: '未登录或登录已过期' });
      const body = await readBody(req);
      store.data[user.id] = sanitizeData(body && body.data);
      saveStore();
      return send(res, 200, { ok: true });
    }

    /* ---------- 静态文件 ---------- */
    if (req.method === 'GET') {
      const file = p === '/' ? '/index.html' : p;
      const full = path.join(ROOT, decodeURIComponent(file));
      if (!full.startsWith(ROOT)) { res.writeHead(403); return res.end('forbidden'); }
      return fs.readFile(full, (err, buf) => {
        if (err) {
          res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
          return res.end('Not Found');
        }
        const ext = path.extname(full).toLowerCase();
        const types = {
          '.html': 'text/html; charset=utf-8',
          '.js': 'text/javascript; charset=utf-8',
          '.css': 'text/css; charset=utf-8',
          '.json': 'application/json; charset=utf-8'
        };
        res.writeHead(200, { 'Content-Type': types[ext] || 'application/octet-stream' });
        res.end(buf);
      });
    }

    send(res, 404, { ok: false, msg: 'Not Found' });
  } catch (e) {
    send(res, 500, { ok: false, msg: e.message || '服务器错误' });
  }
});

loadStore();
server.listen(PORT, () => {
  console.log('========================================');
  console.log('  进出货管理系统已启动');
  console.log('  访问地址：http://localhost:' + PORT);
  console.log('  数据文件：' + DATA_FILE);
  console.log('========================================');
});