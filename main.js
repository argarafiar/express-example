const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const dbConfig = require('./dbConfig');
const verifyToken = require('./middleware');

const app = express();
app.use(bodyParser.json());

app.post('/api/register', async (req, res) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    await dbConfig.execute('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword]);
    res.status(201).send({ data: {
        message: 'User created successfully',
    }
    });
  } catch (error) {
    res.status(400).send(error);
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const [rows] = await dbConfig.execute('SELECT * FROM users WHERE username = ?', [username]);
    if (rows.length === 0) {
      return res.status(401).send('Invalid username or password');
    }
    const user = rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).send('Invalid username or password');
    }
    const token = jwt.sign({ userId: user.id }, 'secret-key', { expiresIn: '1h' });
    res.send({ token });
  } catch (error) {
    res.status(500).send(error);
  }
});

app.post('/api/mahasiswa', verifyToken, async (req, res) => {
  try {
    const { nim, nama } = req.body;
    await dbConfig.execute('INSERT INTO mahasiswa (nim, nama) VALUES (?, ?)', [nim, nama]);
    res.status(201).send({ data: {
        message: 'Mahasiswa created successfully',
    }});
  } catch (error) {
    res.status(400).send(error);
  }
});

app.put('/api/mahasiswa/:id', verifyToken, async (req, res) => {
  try {
    const { nim, nama } = req.body;
    const id = req.params.id;
    await dbConfig.execute('UPDATE mahasiswa SET nim = ?, nama = ? WHERE id = ?', [nim, nama, id]);
    res.send({ data: {
        message: 'Mahasiswa updated successfully',
    }
    });
  } catch (error) {
    res.status(400).send(error);
  }
});

app.delete('/api/mahasiswa/:id', verifyToken, async (req, res) => {
  try {
    const id = req.params.id;
    await dbConfig.execute('DELETE FROM mahasiswa WHERE id = ?', [id]);
    res.send({ data: {
        message: 'Mahasiswa deleted successfully',
    }
    });
  } catch (error) {
    res.status(400).send(error);
  }
});

app.get('/api/mahasiswa', verifyToken, async (req, res) => {
  try {
    const [rows] = await dbConfig.execute('SELECT * FROM mahasiswa');
    res.send({ data: rows });
  } catch (error) {
    res.status(500).send(error);
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server is running on http://localhost:${PORT}`));
