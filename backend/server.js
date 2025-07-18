const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt'); // 🔹 Para encriptar contraseñas

const app = express();
app.use(cors());
app.use(bodyParser.json());

const saltRounds = 10; // 🔹 Nivel de complejidad para bcrypt

// ✅ Conexión a MySQL
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

// ✅ Ruta para registrar usuarios
app.post('/registro', (req, res) => {
  const { nombre, correo, contrasena } = req.body;

  if (!nombre || !correo || !contrasena) {
    return res.status(400).json({ mensaje: 'Todos los campos son obligatorios' });
  }

  // 🔹 Verificar si el correo ya está registrado
  db.query('SELECT * FROM USUARIO WHERE CORREO = ?', [correo], (err, results) => {
    if (err) return res.status(500).json({ mensaje: 'Error en el servidor' });

    if (results.length > 0) {
      return res.status(400).json({ mensaje: 'El correo ya está en uso' });
    }

    // 🔹 Hashear la contraseña antes de guardarla
    bcrypt.hash(contrasena, saltRounds, (err, hash) => {
      if (err) return res.status(500).json({ mensaje: 'Error al procesar la contraseña' });

      // 🔹 Insertar nuevo usuario con contraseña hasheada
      db.query(
        'INSERT INTO USUARIO (NOMBRE, CORREO, CONTRASENNA) VALUES (?, ?, ?)',
        [nombre, correo, hash],
        (err) => {
          if (err) return res.status(500).json({ mensaje: 'Error al registrar el usuario' });
          res.status(200).json({ mensaje: 'Usuario registrado exitosamente' });
        }
      );
    });
  });
});

// ✅ Iniciar el servidor
app.listen(3000, () => {
  console.log('🚀 Servidor corriendo en http://localhost:3000');
});
