import express from 'express';
import dotenv from 'dotenv';
import bcrypt from 'bcrypt';
import { createToken, verifyToken } from './token.js';

dotenv.config();
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

async function hashPassword(pwd) {
  const saltRounds = 10;
  try {
    let salt = await bcrypt.genSalt(saltRounds);
    let hash = await bcrypt.hash(pwd, salt);
    return hash;
  } catch (e) {
    console.log(e);
  }
}

async function checkPassword(plainPwd, hashPwd) {
  //const hashPwd = hashPassword(plainPwd); // this needs to be changed as hash suppose to be stored in db
  try {
    return await bcrypt.compare(plainPwd, hashPwd);
  } catch (e) {
    console.log(e);
  }
}

// verifying token to get access
app.get('/home', (req, res) => {
  const token = req.headers.authorization;

  if (!token) {
    return res
      .status(401)
      .json({ message: 'Unauthorized access. Please provide token' });
  }
  const verifiedToken = verifyToken(token, process.env.JWT_SECRETKEY_STRING);
  if (!verifiedToken) {
    return res.status(401).json({ message: 'Invalid token' });
  }
  res.status(200).json({ message: 'Welcome to home page!' });
});

app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hash = await hashPassword(password);
    if (checkPassword(password, hash)) {
      const token = createToken({ username }, process.env.JWT_SECRETKEY_STRING);
      res.status(200).json({ username, token });
    } else {
      console.log(`Invalid credentials`);
      res.status(401).json({ message: `Invalid credentials` });
    }
  } catch (e) {
    res.status(500).json({ message: `Error authenticating user` });
  }
});

app.listen(process.env.PORT, () => {
  console.log(`App listening on port:${process.env.PORT}`);
});
