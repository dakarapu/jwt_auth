import jwt from 'jsonwebtoken';

export const createToken = (payload, tokenSecret) => {
  return jwt.sign(payload, tokenSecret, { expiresIn: '1h' });
};

export const verifyToken = (token, tokenSecret) => {
  try {
    const verifiedToken = jwt.verify(token, tokenSecret);
    return verifiedToken;
  } catch (e) {
    console.log(`Token verification failed...`);
    return null;
  }
};
