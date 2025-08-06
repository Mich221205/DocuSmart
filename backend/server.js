// =========================
// 📄 server.js completo
// =========================
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.static(__dirname)); 
app.use('/css', express.static(__dirname + '/css'));
app.use(cors());
app.use(express.json());

// 🔹 Configurar MySQL
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '', // agrega tu password si la tienes
  database: 'docusmart'
});

db.connect(err => {
  if (err) {
    console.error('❌ Error al conectar a MySQL:', err);
    return;
  }
  console.log('✅ Conectado a MySQL');
});

const SECRET_KEY = process.env.SECRET_KEY || "miclaveultrasecreta";

// =========================
// 🔹 REGISTRO
// =========================
app.post('/registro', async (req, res) => {
  const { nombre, correo, contrasena } = req.body;

  if (!nombre || !correo || !contrasena) {
    return res.status(400).json({ mensaje: "Todos los campos son obligatorios" });
  }

  const hash = await bcrypt.hash(contrasena, 10);

  db.query(
    "INSERT INTO USUARIO (NOMBRE, CORREO, CONTRASENNA) VALUES (?, ?, ?)",
    [nombre, correo, hash],
    (err, result) => {
      if (err) {
        console.error("❌ Error MySQL:", err);
        return res.status(500).json({ mensaje: "Error en el servidor" });
      }
      res.json({ mensaje: "Usuario registrado con éxito" });
    }
  );
});

// =========================
// 🔹 LOGIN
// =========================
app.post('/login', (req, res) => {
  const { correo, contrasena } = req.body;

  db.query("SELECT * FROM USUARIO WHERE CORREO = ?", [correo], async (err, results) => {
    if (err) return res.status(500).json({ mensaje: "Error en el servidor" });
    if (results.length === 0) return res.status(401).json({ mensaje: "Usuario no encontrado" });

    const usuario = results[0];

    // 🟢 Depuración
    console.log("Usuario encontrado:", usuario);
    console.log("Contraseña recibida:", contrasena);
    console.log("Hash en BD:", usuario.CONTRASENNA);

    if (!contrasena || !usuario.CONTRASENNA) {
      return res.status(400).json({ mensaje: "Datos incompletos para comparar contraseñas" });
    }

    const match = await bcrypt.compare(contrasena, usuario.CONTRASENNA);

    if (!match) return res.status(401).json({ mensaje: "Contraseña incorrecta" });

    const token = jwt.sign({ id: usuario.ID_USUARIO }, SECRET_KEY, { expiresIn: "1h" });
    res.json({ mensaje: "Login correcto", token });
  });
});

// =========================
// 🔹 OBTENER PERFIL
// =========================
app.get("/perfil", (req, res) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ mensaje: "Token no proporcionado" });

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const userId = decoded.id;

  const sql = `
    SELECT 
      u.ID_USUARIO, 
      u.NOMBRE, 
      u.CORREO,
      GROUP_CONCAT(g.DESCRIPCION) AS PREFERENCIAS
    FROM USUARIO u
    LEFT JOIN PREFERENCIAS p ON u.ID_USUARIO = p.ID_USUARIO
    LEFT JOIN GENERO g ON p.ID_GENERO = g.ID_GENERO
    WHERE u.ID_USUARIO = ?
    GROUP BY u.ID_USUARIO, u.NOMBRE, u.CORREO
  `;


    db.query(sql, [userId], (err, results) => {
      if (err) return res.status(500).json({ mensaje: "Error en la base de datos" });
      if (results.length === 0) return res.status(404).json({ mensaje: "Usuario no encontrado" });

      const row = results[0];
      const preferencias = row.PREFERENCIAS ? row.PREFERENCIAS.split(",") : [];

      res.json({
        ID_USUARIO: row.ID_USUARIO,
        NOMBRE: row.NOMBRE,
        CORREO: row.CORREO,
        PREFERENCIAS: preferencias
      });
    });

  } catch {
    return res.status(403).json({ mensaje: "Token inválido o expirado" });
  }
});

// =========================
// 🔹 ACTUALIZAR PREFERENCIAS
// =========================
app.put("/perfil", (req, res) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ mensaje: "Token no proporcionado" });

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    const userId = decoded.id;
    const { preferencias } = req.body; // ["Ciencia","Arte"]

    db.query("DELETE FROM PREFERENCIAS WHERE ID_USUARIO = ?", [userId], (err) => {
      if (err) return res.status(500).json({ mensaje: "Error al limpiar preferencias" });

      if (!preferencias || preferencias.length === 0) {
        return res.json({ mensaje: "Preferencias actualizadas" });
      }

      // Obtener IDs de GENERO
      const placeholders = preferencias.map(() => "?").join(",");
      db.query(
        `SELECT ID_GENERO, DESCRIPCION FROM GENERO WHERE DESCRIPCION IN (${placeholders})`,
        preferencias,
        (err2, rows) => {
          if (err2) return res.status(500).json({ mensaje: "Error al buscar géneros" });

          // Mapear IDs
          const values = rows.map(r => [userId, r.ID_GENERO]);

          console.log("Valores a insertar:", values);

          db.query(
            "INSERT INTO PREFERENCIAS (ID_USUARIO, ID_GENERO) VALUES ?",
            [values],
            (err3) => {
              if (err3) return res.status(500).json({ mensaje: "Error al guardar preferencias" });
              res.json({ mensaje: "Preferencias guardadas correctamente" });
            }
          );
        }
      );
    });
  } catch {
    return res.status(403).json({ mensaje: "Token inválido o expirado" });
  }
});

// =========================
// 🔹 RECOMENDACIONES PERSONALIZADAS
// =========================
app.get('/recomendaciones/:idUsuario', (req, res) => {
  const userId = req.params.idUsuario;

  const sql = `
    SELECT 
      d.ID_DOCUMENTAL,
      d.TITULO,
      d.DESCRIPCION,
      g.DESCRIPCION AS GENERO,
      MAX(img.ruta_imagen) AS ruta_imagen
    FROM documental d
    JOIN preferencias p ON d.ID_GENERO = p.ID_GENERO
    JOIN genero g ON d.ID_GENERO = g.ID_GENERO
    LEFT JOIN historial_visualizacion hv ON d.ID_DOCUMENTAL = hv.ID_DOCUMENTAL AND hv.ID_USUARIO = ?
    LEFT JOIN imagenes_documentales img ON d.ID_DOCUMENTAL = img.id_documental
    WHERE p.ID_USUARIO = ?
      AND hv.ID_DOCUMENTAL IS NULL
    GROUP BY d.ID_DOCUMENTAL, d.TITULO, d.DESCRIPCION, g.DESCRIPCION
    LIMIT 10
  `;

  db.query(sql, [userId, userId], (err, results) => {
    if (err) {
      console.error("❌ Error en recomendaciones:", err);
      return res.status(500).json({ mensaje: "Error al obtener recomendaciones" });
    }

    res.json(results);
  });
});

app.get('/documental/:id', (req, res) => {
  console.log("📥 Petición recibida para ID:", req.params.id); // <--- agregá esto

  const id = req.params.id;
  const sql = `
    SELECT 
      d.ID_DOCUMENTAL,
      d.TITULO,
      d.DESCRIPCION,
      d.DURACION,
      d.FECHA_PUBLICACIÓN,
      g.DESCRIPCION AS GENERO,
      vd.ruta_video,
      img.ruta_imagen
    FROM documental d
    JOIN genero g ON d.ID_GENERO = g.ID_GENERO
    LEFT JOIN video_documentales vd ON d.ID_DOCUMENTAL = vd.ID_DOCUMENTAL
    LEFT JOIN imagenes_documentales img ON d.ID_DOCUMENTAL = img.id_documental
    WHERE d.ID_DOCUMENTAL = ?
  `;

  db.query(sql, [id], (err, results) => {
    if (err) {
      console.error("❌ Error SQL:", err);
      return res.status(500).json({ mensaje: "Error al obtener documental" });
    }

    if (results.length === 0) {
      console.warn("⚠️ Documental no encontrado para ID:", id);
      return res.status(404).json({ mensaje: "Documental no encontrado" });
    }

    res.json(results[0]);
  });
});

// =========================
// 🔹 INICIAR SERVIDOR
// =========================
const PORT = 3000;
app.listen(PORT, () => console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`));
