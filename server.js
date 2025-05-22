/* === server.js === */
const express = require('express');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

const app = express();
const DATA_FILE = path.join(__dirname, 'data', 'users.json');

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { maxAge: 24 * 60 * 60 * 1000 } // 1 天
}));

function readUsers() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
  } catch {
    return {};
  }
}

function writeUsers(users) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(users, null, 2));
}

function requireLogin(req, res, next) {
  if (!req.session.username) {
    return res.status(401).json({ success: false, message: '尚未登入' });
  }
  next();
}

app.post('/api/register', async (req, res) => {
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
});

app.post('/api/login', async (req, res) => {
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
});

app.post('/api/logout', requireLogin, (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true, message: '已登出' });
  });
});

app.get('/api/me', requireLogin, (req, res) => {
  const users = readUsers();
  const user = users[req.session.username];
  res.json({ success: true, username: req.session.username, profile: user.profile });
});

app.post('/api/profile', requireLogin, (req, res) => {
  const { name, avatar, initialAmount } = req.body;
  const users = readUsers();
  const user = users[req.session.username];

  if (!user) return res.status(400).json({ success: false, message: '使用者不存在' });

  if (user.profile.initialAmount != null && initialAmount !== undefined) {
    return res.status(403).json({ success: false, message: '現有金額已設定，無法更改' });
  }

  if (name) user.profile.name = name;
  if (avatar) user.profile.avatar = avatar;
  if (initialAmount !== undefined) {
    if (typeof initialAmount !== 'number' || initialAmount < 0) {
      return res.status(400).json({ success: false, message: '現有金額必須是 0 或以上數字' });
    }
    user.profile.initialAmount = initialAmount;
  }

  writeUsers(users);
  res.json({ success: true, profile: user.profile });
});

app.get('/api/records', requireLogin, (req, res) => {
  const users = readUsers();
  const user = users[req.session.username];
  res.json({ success: true, records: user.records });
});

app.post('/api/records', requireLogin, (req, res) => {
  const { category, amount, type, date, note } = req.body;
  if (!category || !amount || !type || !date) {
    return res.status(400).json({ success: false, message: '缺少必要欄位' });
  }
  const users = readUsers();
  const user = users[req.session.username];

  const id = Date.now().toString();
  const record = { id, category, amount: Number(amount), type, date, note: note || '' };

  user.records.push(record);
  writeUsers(users);
  res.json({ success: true, record });
});

app.put('/api/records/:id', requireLogin, (req, res) => {
  const { id } = req.params;
  const { category, amount, type, date, note } = req.body;
  const users = readUsers();
  const user = users[req.session.username];

  const record = user.records.find(r => r.id === id);
  if (!record) return res.status(404).json({ success: false, message: '記錄未找到' });

  if (category) record.category = category;
  if (amount) record.amount = Number(amount);
  if (type) record.type = type;
  if (date) record.date = date;
  if (note !== undefined) record.note = note;

  writeUsers(users);
  res.json({ success: true, record });
});

app.delete('/api/records/:id', requireLogin, (req, res) => {
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
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
