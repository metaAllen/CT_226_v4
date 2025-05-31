const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(cors());
app.use(express.json());

// 請根據你的 MongoDB 連線字串修改
const MONGO_URL = 'mongodb://localhost:27017/tri_v2';
mongoose.connect(MONGO_URL, { useNewUrlParser: true, useUnifiedTopology: true });

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true },
  password: String,
  data: Object // 用戶所有同步資料
});
const User = mongoose.model('User', userSchema);

const JWT_SECRET = 'tri_v2_secret_key'; // 請改成更安全的 key

// 註冊
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: '缺少帳號或密碼' });
  const exist = await User.findOne({ username });
  if (exist) return res.status(409).json({ error: '帳號已存在' });
  const hash = await bcrypt.hash(password, 10);
  const user = new User({ username, password: hash, data: {} });
  await user.save();
  res.json({ success: true });
});

// 登入
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(401).json({ error: '帳號或密碼錯誤' });
  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: '帳號或密碼錯誤' });
  const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token });
});

// 取得用戶資料
app.get('/api/data', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: '缺少 token' });
  try {
    const { userId } = jwt.verify(token, JWT_SECRET);
    const user = await User.findById(userId);
    res.json({ data: user.data || {} });
  } catch {
    res.status(401).json({ error: 'token 無效' });
  }
});

// 儲存用戶資料
app.post('/api/data', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: '缺少 token' });
  try {
    const { userId } = jwt.verify(token, JWT_SECRET);
    await User.findByIdAndUpdate(userId, { data: req.body.data });
    res.json({ success: true });
  } catch {
    res.status(401).json({ error: 'token 無效' });
  }
});

app.listen(3001, () => console.log('Server running on http://localhost:3001')); 