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

// Middleware para verificar que el usuario sea admin
function soloAdmin(req, res, next) {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ mensaje: "Token no proporcionado" });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    if (decoded.rol !== "admin") {
      return res.status(403).json({ mensaje: "No tienes permisos de administrador" });
    }
    req.user = decoded; // opcional, por si quieres usar datos del usuario en la ruta
    next();
  } catch (err) {
    return res.status(403).json({ mensaje: "Token inválido o expirado" });
  }
}

app.use(express.static(__dirname)); 
app.use('/css', express.static(__dirname + '/css'));
app.use(cors());
app.use(express.json());

// 🔹 Configurar MySQL
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '', 
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
// 🔹 LOGIN (bloquea usuario inactivo)
// =========================
app.post('/login', (req, res) => {
  const { correo, contrasena } = req.body;

  // ✅ Solo busca usuarios activos
  db.query(
    "SELECT * FROM USUARIO WHERE CORREO = ? AND ESTADO = 1",
    [correo],
    async (err, results) => {
      if (err) return res.status(500).json({ mensaje: "Error en el servidor" });

      // Si no encuentra, o está inactivo, mensaje genérico
      if (results.length === 0) {
        return res.status(401).json({ mensaje: "Usuario no encontrado o inactivo" });
      }

      const usuario = results[0];

      // 🔍 Verificación extra por seguridad
      if (Number(usuario.ESTADO) !== 1) {
        return res.status(403).json({ mensaje: "Usuario inactivo. Contacte al administrador." });
      }

      if (!contrasena || !usuario.CONTRASENNA) {
        return res.status(400).json({ mensaje: "Datos incompletos para comparar contraseñas" });
      }

      const match = await bcrypt.compare(contrasena, usuario.CONTRASENNA);
      if (!match) {
        return res.status(401).json({ mensaje: "Contraseña incorrecta" });
      }

      // 🔹 Incluimos el ROL en el token
      const token = jwt.sign(
        { id: usuario.ID_USUARIO, rol: usuario.ROL || 'usuario' },
        SECRET_KEY,
        { expiresIn: "1h" }
      );

      res.json({
        mensaje: "Login correcto",
        token,
        rol: usuario.ROL || 'usuario'
      });
    }
  );
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
// 🔹 COMENTARIOS
// =========================

// Insertar comentario
app.post('/comentarios', (req, res) => {
  const { id_usuario, id_documental, comentario } = req.body;

  if (!comentario || comentario.trim() === '') {
    return res.status(400).json({ mensaje: "Comentario vacío no permitido" });
  }

  const sql = `
    INSERT INTO comentarios (ID_USUARIO, ID_DOCUMENTAL, COMENTARIO)
    VALUES (?, ?, ?)`;

  db.query(sql, [id_usuario, id_documental, comentario], (err) => {
    if (err) return res.status(500).json({ mensaje: "Error al agregar comentario" });
    res.json({ mensaje: "Comentario agregado correctamente" });
  });
});

// Obtener comentarios por documental
app.get('/comentarios/:id_documental', (req, res) => {
  const { id_documental } = req.params;

  const sql = `
    SELECT c.COMENTARIO, c.FECHA_COMENTARIO, u.NOMBRE
    FROM comentarios c
    JOIN usuario u ON c.ID_USUARIO = u.ID_USUARIO
    WHERE c.ID_DOCUMENTAL = ? AND c.ESTADO = 1
    ORDER BY c.FECHA_COMENTARIO DESC`;

  db.query(sql, [id_documental], (err, resultados) => {
    if (err) return res.status(500).json({ mensaje: "Error al obtener comentarios" });
    res.json(resultados);
  });
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
      AND d.ESTADO = 1
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
    AND d.ESTADO = 1
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

app.post('/reaccion', (req, res) => {
  const { id_usuario, id_documental, tipo_reaccion } = req.body;

  const sql = `
    INSERT INTO reacciones (ID_USUARIO, ID_DOCUMENTAL, TIPO_REACCION)
    VALUES (?, ?, ?)
    ON DUPLICATE KEY UPDATE 
      TIPO_REACCION = VALUES(TIPO_REACCION), 
      FECHA_REACCION = CURRENT_TIMESTAMP
  `;

  db.query(sql, [id_usuario, id_documental, tipo_reaccion], (err, result) => {
    if (err) {
      console.error('❌ Error al registrar reacción:', err);
      return res.status(500).json({ mensaje: "Error al registrar reacción" });
    }

    res.json({ mensaje: "Reacción registrada correctamente" });
  });
});

// Eliminar reacción existente
app.delete('/reaccion/:idUsuario/:idDocumental', (req, res) => {
  const { idUsuario, idDocumental } = req.params;
  const sql = "DELETE FROM reacciones WHERE ID_USUARIO = ? AND ID_DOCUMENTAL = ?";
  db.query(sql, [idUsuario, idDocumental], (err) => {
    if (err) return res.status(500).json({ mensaje: "Error al eliminar reacción" });
    res.json({ mensaje: "Reacción eliminada correctamente" });
  });
});


app.get('/reaccion/:idUsuario/:idDocumental', (req, res) => {
  const { idUsuario, idDocumental } = req.params;

  const sql = `
    SELECT TIPO_REACCION 
    FROM reacciones 
    WHERE ID_USUARIO = ? AND ID_DOCUMENTAL = ?
    ORDER BY FECHA_REACCION DESC
    LIMIT 1
  `;

  db.query(sql, [idUsuario, idDocumental], (err, results) => {
    if (err) return res.status(500).json({ mensaje: "Error al obtener reacción" });
    if (results.length === 0) return res.json({ tipo_reaccion: null });

    res.json({ tipo_reaccion: results[0].TIPO_REACCION });
  });
});

app.get("/admin/documentales", soloAdmin, (req, res) => {
  const sql = `
    SELECT d.ID_DOCUMENTAL, d.TITULO, d.DURACION, g.DESCRIPCION AS GENERO, d.ESTADO
    FROM documental d
    JOIN genero g ON d.ID_GENERO = g.ID_GENERO
    ORDER BY d.ID_DOCUMENTAL DESC
  `;
  
  db.query(sql, (err, results) => {
    if (err) {
      console.error("❌ Error al obtener documentales:", err);
      return res.status(500).json({ mensaje: "Error en la base de datos" });
    }
    res.json(results || []);
  });
});

// 📌 Listar documentales (solo activos para usuarios, todos para admin)
app.get("/admin/documentales", (req, res) => {
  const sql = `
    SELECT d.ID_DOCUMENTAL, d.TITULO, d.DURACION, g.DESCRIPCION AS GENERO, d.ESTADO
    FROM documental d
    JOIN genero g ON d.ID_GENERO = g.ID_GENERO
    ORDER BY d.ID_DOCUMENTAL DESC
  `;
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ mensaje: "Error en la base de datos" });
    res.json(results);
  });
});

// 📌 Inactivar documental
app.put("/admin/documentales/:id/inactivar", (req, res) => {
  const id = req.params.id;
  const sql = "UPDATE documental SET ESTADO = 0 WHERE ID_DOCUMENTAL = ?";
  db.query(sql, [id], (err, result) => {
    if (err) return res.status(500).json({ mensaje: "Error al inactivar documental" });
    res.json({ mensaje: "Documental inactivado correctamente" });
  });
});

// 📌 Reactivar documental
app.put("/admin/documentales/:id/activar", (req, res) => {
  const id = req.params.id;
  const sql = "UPDATE documental SET ESTADO = 1 WHERE ID_DOCUMENTAL = ?";
  db.query(sql, [id], (err, result) => {
    if (err) return res.status(500).json({ mensaje: "Error al activar documental" });
    res.json({ mensaje: "Documental activado correctamente" });
  });
});

// =========================
// 🔹 LISTAR USUARIOS (solo admin)
// =========================
app.get("/admin/usuarios", soloAdmin, (req, res) => {
  const sql = `
    SELECT ID_USUARIO, NOMBRE, CORREO, ROL, FECHA_REGISTRO, ESTADO
    FROM usuario
    ORDER BY FECHA_REGISTRO DESC
  `;
  db.query(sql, (err, results) => {
    if (err) {
      console.error("❌ Error al obtener usuarios:", err);
      return res.status(500).json({ mensaje: "Error al obtener usuarios" });
    }
    res.json(results || []);
  });
});

// =========================
// 🔹 CAMBIAR ESTADO DE USUARIO (solo admin)
// =========================
app.put("/admin/usuarios/:id/estado", soloAdmin, (req, res) => {
  const { id } = req.params;
  const { estado } = req.body;

  if (estado !== 0 && estado !== 1) {
    return res.status(400).json({ mensaje: "Estado inválido" });
  }

  const sql = "UPDATE usuario SET ESTADO = ? WHERE ID_USUARIO = ?";
  db.query(sql, [estado, id], (err, result) => {
    if (err) {
      console.error("❌ Error al cambiar estado:", err);
      return res.status(500).json({ mensaje: "Error al cambiar estado" });
    }
    res.json({ mensaje: `Usuario ${estado === 1 ? "activado" : "inactivado"} correctamente` });
  });
});

// =========================
// 🔹 EDITAR USUARIO (solo admin)
// =========================
app.put("/admin/usuarios/:id", soloAdmin, (req, res) => {
  const { id } = req.params;
  const { nombre, correo, rol } = req.body;

  if (!nombre || !rol) {
    return res.status(400).json({ mensaje: "Nombre y rol son obligatorios" });
  }

  const sql = "UPDATE usuario SET NOMBRE = ?, CORREO = ?, ROL = ? WHERE ID_USUARIO = ?";
  db.query(sql, [nombre, correo, rol, id], (err, result) => {
    if (err) {
      console.error("❌ Error al actualizar usuario:", err);
      return res.status(500).json({ mensaje: "Error al actualizar usuario" });
    }
    res.json({ mensaje: "Usuario actualizado correctamente" });
  });
});

app.get("/admin/comentarios", soloAdmin, (req, res) => {
  const sql = `
    SELECT c.ID_COMENTARIO, u.NOMBRE AS NOMBRE_USUARIO, d.TITULO AS TITULO_DOCUMENTAL,
           c.COMENTARIO, c.FECHA_COMENTARIO, c.ESTADO
    FROM comentarios c
    JOIN usuario u ON c.ID_USUARIO = u.ID_USUARIO
    JOIN documental d ON c.ID_DOCUMENTAL = d.ID_DOCUMENTAL
    ORDER BY c.FECHA_COMENTARIO DESC
  `;
  db.query(sql, (err, results) => {
    if (err) {
      console.error("❌ Error al obtener comentarios:", err);
      return res.status(500).json({ mensaje: "Error al obtener comentarios" });
    }
    res.json(results || []);
  });
});

app.put("/admin/comentarios/:id/estado", soloAdmin, (req, res) => {
  const { id } = req.params;
  const { estado } = req.body;

  if (estado !== 0 && estado !== 1) {
    return res.status(400).json({ mensaje: "Estado inválido" });
  }

  const sql = "UPDATE comentarios SET ESTADO = ? WHERE ID_COMENTARIO = ?";
  db.query(sql, [estado, id], (err, result) => {
    if (err) {
      console.error("❌ Error al cambiar estado del comentario:", err);
      return res.status(500).json({ mensaje: "Error al cambiar estado del comentario" });
    }
    res.json({ mensaje: `Comentario ${estado === 1 ? "activado" : "inactivado"} correctamente` });
  });
});


// =========================
// 🔹 INICIAR SERVIDOR
// =========================
const PORT = 3000;
app.listen(PORT, () => console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`));
