const jwt = require('jsonwebtoken');

const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).send('A token is required for authentication');
    try {
      const decoded = jwt.verify(token, 'secret-key');
      req.user = decoded;
      next();
    } catch (error) {
      res.status(401).send('Invalid Token');
    }
  };

module.exports = verifyToken;