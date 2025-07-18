const express = require('express');
const mysql = require('mysql2');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt'); 
const jwt = require('jsonwebtoken');
require('dotenv').config(); // ✅ Para usar la SECRET_KEY desde .env

const app = express();
app.use(cors());
app.use(bodyParser.json());

const saltRounds = 10;
const SECRET_KEY = process.env.SECRET_KEY; // ✅ Clave secreta para JWT

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

// ✅ REGISTRO
app.post('/registro', (req, res) => {
  const { nombre, correo, contrasena } = req.body;

  if (!nombre || !correo || !contrasena) {
    return res.status(400).json({ mensaje: 'Todos los campos son obligatorios' });
  }

  db.query('SELECT * FROM USUARIO WHERE CORREO = ?', [correo], (err, results) => {
    if (err) return res.status(500).json({ mensaje: 'Error en el servidor' });

    if (results.length > 0) {
      return res.status(400).json({ mensaje: 'El correo ya está en uso' });
    }

    bcrypt.hash(contrasena, saltRounds, (err, hash) => {
      if (err) return res.status(500).json({ mensaje: 'Error al procesar la contraseña' });

      console.log("✅ Contraseña hasheada:", hash);

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

// ✅ LOGIN (Devuelve un token JWT)
app.post('/login', (req, res) => {
  const { correo, contrasena } = req.body;

  if (!correo || !contrasena) {
    return res.status(400).json({ mensaje: 'Todos los campos son obligatorios' });
  }

  db.query('SELECT * FROM USUARIO WHERE CORREO = ?', [correo], (err, results) => {
    if (err) return res.status(500).json({ mensaje: 'Error en el servidor' });

    if (results.length === 0) {
      return res.status(400).json({ mensaje: 'Correo o contraseña incorrectos' });
    }

    const usuario = results[0];

    bcrypt.compare(contrasena, usuario.CONTRASENNA, (err, esValida) => {
      if (err) return res.status(500).json({ mensaje: 'Error al procesar la contraseña' });

      if (!esValida) {
        return res.status(400).json({ mensaje: 'Correo o contraseña incorrectos' });
      }

    const token = jwt.sign(
      { id: usuario.ID_USUARIO, correo: usuario.CORREO },
      SECRET_KEY,
      { expiresIn: '2h' }
    );


      res.status(200).json({ mensaje: 'Login exitoso', token });
    });
  });
});

// ✅ Middleware para verificar el token
function verificarToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ mensaje: 'Token requerido' });

  jwt.verify(token, SECRET_KEY, (err, usuario) => {
    if (err) return res.status(403).json({ mensaje: 'Token inválido o expirado' });

    req.usuario = usuario;
    next();
  });
}

// ✅ PERFIL (Ruta protegida)
app.get('/perfil', verificarToken, (req, res) => {
  const userId = req.usuario.id;

  db.query('SELECT ID_USUARIO, NOMBRE, CORREO FROM USUARIO WHERE ID_USUARIO = ?', [userId], (err, results) => {
    if (err) return res.status(500).json({ mensaje: 'Error en el servidor' });

    if (results.length === 0) {
      return res.status(404).json({ mensaje: 'Usuario no encontrado' });
    }

    res.status(200).json(results[0]);
  });
});

// ✅ Iniciar el servidor
app.listen(3000, () => {
  console.log('🚀 Servidor corriendo en http://localhost:3000');
});
