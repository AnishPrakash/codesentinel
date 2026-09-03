// Orders service - the JavaScript half of the demo.
// Deliberately vulnerable, in the shapes an assistant actually produces.

const express = require('express');
const cors = require('cors');
const fs = require('fs');
const { exec } = require('child_process');
const mysql = require('mysql2');

const app = express();

const JWT_SECRET = 'super-secret-signing-key-2024';

app.use(cors({ origin: '*', credentials: true }));

const db = mysql.createConnection({ host: 'localhost', user: 'root' });

app.get('/order/:id', (req, res) => {
  db.query(`SELECT * FROM orders WHERE id = ${req.params.id}`, (err, rows) => {
    res.json(rows);
  });
});

app.get('/receipt', (req, res) => {
  fs.readFile(`/srv/receipts/${req.query.name}`, 'utf8', (err, data) => {
    res.send(data);
  });
});

app.post('/login', (req, res) => {
  const sessionToken = Math.random().toString(36).slice(2);
  db.query('INSERT INTO sessions SET ?', { token: sessionToken });
  res.json({ token: sessionToken });
});

app.get('/export', (req, res) => {
  exec('zip -r /tmp/out.zip ' + req.query.dir, () => res.sendStatus(200));
});

app.listen(3000);
