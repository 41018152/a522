/* === server.js === */
const express = require('express');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

const app = express();
const DATA_DIR = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'users.json');

// 確保資料夾和檔案存在
function ensureDataFile() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR);
  }
  if (!fs.existsSync(DATA_FILE)) {
    fs.writeFileSync(DATA_FILE, '{}');
  }
}

function readUsers() {
  try {
    ensureDataFile();
    const data = fs.readFileSync(DATA_FILE, 'utf8');
    return JSON.parse(data);
  } catch (e) {
    console.error('讀取 users.json 失敗:', e);
    return {};
  }
}

function writeUsers(users) {
  try {
    ensureDataFile();
    fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2));
  } catch (e) {
    console.error('寫入 users.json 失敗:', e);
    throw e;
  }
}

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  name: 'sid',
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 24 * 60 * 60 * 1000, // 1 天
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // 只在 https 下傳送 cookie
    sameSite: 'lax',
  }
}));

function requireLogin(req, res, next) {
  if (!req.session.username) {
    return res.status(401).json({ success: false, message: '尚未登入' });
  }
  next();
}

// 輔助函數：驗證金額欄位
function validateAmount(amount) {
  return typeof amount === 'number' && !isNaN(amount) && amount >= 0;
}

// 只回傳 user 重要資料，不回傳密碼
function getPublicUser(user) {
  if (!user) return null;
  return {
    profile: user.profile || {},
    records: user.records || [],
  };
}

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ success: false, message: '帳號密碼不可空白' });

    const users = readUsers();
    if (users[username]) return res.status(400).json({ success: false, message: '帳號已存在' });

    const hashedPassword = await bcrypt.hash(password, 10);

    users[username] = {
      password: hashedPassword,
      profile: { name: username },
      records: []
    };
    writeUsers(users);
    res.json({ success: true, message: '註冊成功' });
  } catch (e) {
    console.error('註冊失敗:', e);
    res.status(500).json({ success: false, message: '伺服器錯誤' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const users = readUsers();
    if (!users[username]) {
      return res.status(400).json({ success: false, message: '帳號或密碼錯誤' });
    }

    const valid = await bcrypt.compare(password, users[username].password);
    if (!valid) {
      return res.status(400).json({ success: false, message: '帳號或密碼錯誤' });
    }

    req.session.username = username;
    res.json({ success: true, message: '登入成功', username });
  } catch (e) {
    console.error('登入失敗:', e);
    res.status(500).json({ success: false, message: '伺服器錯誤' });
  }
});

app.post('/api/logout', requireLogin, (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true, message: '已登出' });
  });
});

app.get('/api/me', requireLogin, (req, res) => {
  try {
    const users = readUsers();
    const user = users[req.session.username];
    if (!user) return res.status(404).json({ success: false, message: '使用者不存在' });
    res.json({ success: true, username: req.session.username, profile: user.profile });
  } catch (e) {
    console.error('取得使用者資訊錯誤:', e);
    res.status(500).json({ success: false, message: '伺服器錯誤' });
  }
});

// 新增: 讀取指定使用者資訊，不含密碼，給前端用
app.get('/api/user/:username', (req, res) => {
  try {
    const { username } = req.params;
    const users = readUsers();
    const user = users[username];
    if (!user) return res.status(404).json({ success: false, message: '使用者不存在' });

    const publicUser = getPublicUser(user);
    res.json({ success: true, username, data: publicUser });
  } catch (e) {
    console.error('取得指定使用者錯誤:', e);
    res.status(500).json({ success: false, message: '伺服器錯誤' });
  }
});

app.post('/api/profile', requireLogin, (req, res) => {
  try {
    const { name, avatar, initialAmount } = req.body;
    const users = readUsers();
    const user = users[req.session.username];

    if (!user) return res.status(400).json({ success: false, message: '使用者不存在' });

    // 初始金額一旦設定過就不能修改
    if (user.profile.initialAmount != null && initialAmount !== undefined) {
      return res.status(403).json({ success: false, message: '現有金額已設定，無法更改' });
    }

    if (name) user.profile.name = name;
    if (avatar) user.profile.avatar = avatar;
    if (initialAmount !== undefined) {
      if (!validateAmount(initialAmount)) {
        return res.status(400).json({ success: false, message: '現有金額必須是 0 或以上數字' });
      }
      user.profile.initialAmount = initialAmount;
    }

    writeUsers(users);
    res.json({ success: true, profile: user.profile });
  } catch (e) {
    console.error('更新個人資料失敗:', e);
    res.status(500).json({ success: false, message: '伺服器錯誤' });
  }
});

app.get('/api/records', requireLogin, (req, res) => {
  try {
    const users = readUsers();
    const user = users[req.session.username];
    if (!user) return res.status(404).json({ success: false, message: '使用者不存在' });
    res.json({ success: true, records: user.records });
  } catch (e) {
    console.error('取得記錄錯誤:', e);
    res.status(500).json({ success: false, message: '伺服器錯誤' });
  }
});

app.post('/api/records', requireLogin, (req, res) => {
  try {
    const { category, amount, type, date, note } = req.body;
    if (!category || amount === undefined || !type || !date) {
      return res.status(400).json({ success: false, message: '缺少必要欄位' });
    }
    if (!validateAmount(Number(amount))) {
      return res.status(400).json({ success: false, message: '金額需為非負數字' });
    }

    const users = readUsers();
    const user = users[req.session.username];

    const id = Date.now().toString();
    const record = { id, category, amount: Number(amount), type, date, note: note || '' };

    user.records.push(record);
    writeUsers(users);
    res.json({ success: true, record });
  } catch (e) {
    console.error('新增記錄失敗:', e);
    res.status(500).json({ success: false, message: '伺服器錯誤' });
  }
});

app.put('/api/records/:id', requireLogin, (req, res) => {
  try {
    const { id } = req.params;
    const { category, amount, type, date, note } = req.body;
    const users = readUsers();
    const user = users[req.session.username];

    const record = user.records.find(r => r.id === id);
    if (!record) return res.status(404).json({ success: false, message: '記錄未找到' });

    if (category) record.category = category;
    if (amount !== undefined) {
      if (!validateAmount(Number(amount))) {
        return res.status(400).json({ success: false, message: '金額需為非負數字' });
      }
      record.amount = Number(amount);
    }
    if (type) record.type = type;
    if (date) record.date = date;
    if (note !== undefined) record.note = note;

    writeUsers(users);
    res.json({ success: true, record });
  } catch (e) {
    console.error('更新記錄失敗:', e);
    res.status(500).json({ success: false, message: '伺服器錯誤' });
  }
});

app.delete('/api/records/:id', requireLogin, (req, res) => {
  try {
    const id = req.params.id;
    const users = readUsers();
    const user = users[req.session.username];
    const beforeLen = user.records.length;
    user.records = user.records.filter(r => r.id !== id);
    if (user.records.length === beforeLen) {
      return res.status(404).json({ success: false, message: '找不到該筆記錄' });
    }
    writeUsers(users);
    res.json({ success: true, message: '刪除成功' });
  } catch (e) {
    console.error('刪除記錄失敗:', e);
    res.status(500).json({ success: false, message: '伺服器錯誤' });
  }
});

// 刪除帳號，會刪除帳號所有資料並登出
app.delete('/api/account', requireLogin, (req, res) => {
  try {
    const users = readUsers();
    const username = req.session.username;

    if (!users[username]) {
      return res.status(404).json({ success: false, message: '使用者不存在' });
    }

    delete users[username];
    writeUsers(users);

    req.session.destroy(err => {
      if (err) {
        console.error('刪除帳號時銷毀 session 失敗:', err);
        return res.status(500).json({ success: false, message: '伺服器錯誤' });
      }
      res.json({ success: true, message: '帳號已刪除' });
    });
  } catch (e) {
    console.error('刪除帳號失敗:', e);
    res.status(500).json({ success: false, message: '伺服器錯誤' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
