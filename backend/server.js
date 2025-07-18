const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const db = mysql.createConnection({
  host: 'localhost',
  port: 3306,                
  user: 'root',
  database: 'docusmart'
});

db.connect(err => {
  if (err) {
    console.error('❌ Error al conectar a MySQL:', err);
    return;
  }
  console.log('✅ Conectado a MySQL');
});

app.post('/registro', (req, res) => {
  const { nombre, correo, contrasena } = req.body;

  if (!nombre || !correo || !contrasena) {
    return res.status(400).json({ mensaje: 'Todos los campos son obligatorios' });
  }

  // Verificar si el correo ya está registrado
  db.query('SELECT * FROM USUARIO WHERE CORREO = ?', [correo], (err, results) => {
    if (err) return res.status(500).json({ mensaje: 'Error en el servidor' });

    if (results.length > 0) {
      return res.status(400).json({ mensaje: 'El correo ya está en uso' });
    }

    // Insertar nuevo usuario
    db.query(
      'INSERT INTO USUARIO (NOMBRE, CORREO, CONTRASENNA) VALUES (?, ?, ?)',
      [nombre, correo, contrasena],
      (err) => {
        if (err) return res.status(500).json({ mensaje: 'Error al registrar el usuario' });
        res.status(200).json({ mensaje: 'Usuario registrado exitosamente' });
      }
    );
  });
});

// ✅ Iniciar el servidor
app.listen(3000, () => {
  console.log('🚀 Servidor corriendo en http://localhost:3000');
});
