const express = require("express");
const { Pool } = require("pg");
const app = express();

//  Configuración de la base de datos
const pool = new Pool({
  user: "williamscamacaro",
  host: "localhost",
  database: "nanacao_db",
  password: "",
  port: 5432,
});

const PORT = process.env.PORT || 3000;

app.use(express.json());

// Ruta GET /cafes
app.get("/cafes", async (req, res) => {
  try {
    const result = await pool.query("SELECT * FROM cafes");
    res.status(200).send(result.rows);
  } catch (err) {
    res.status(500).send(err);
  }
});

// Ruta GET /cafes/:id
app.get("/cafes/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query("SELECT * FROM cafes WHERE id = $1", [id]);
    if (result.rows.length > 0) {
      res.status(200).send(result.rows[0]);
    } else {
      res
        .status(404)
        .send({ message: "No se encontró ningún cafe con ese id" });
    }
  } catch (err) {
    res.status(500).send(err);
  }
});

// Ruta POST /cafes
app.post("/cafes", async (req, res) => {
  const { nombre } = req.body;
  try {
    const result = await pool.query(
      "INSERT INTO cafes (nombre) VALUES ($1) RETURNING *",
      [nombre]
    );
    res.status(201).send(result.rows[0]);
  } catch (err) {
    res.status(500).send(err);
  }
});

// Ruta PUT /cafes/:id
app.put("/cafes/:id", async (req, res) => {
  const { id } = req.params;
  const { nombre } = req.body;

  try {
    if (id != req.body.id) {
      return res.status(400).send({
        message: "El id del parámetro no coincide con el id del café recibido",
      });
    }

    const result = await pool.query(
      "UPDATE cafes SET nombre = $1 WHERE id = $2 RETURNING *",
      [nombre, id]
    );
    if (result.rows.length > 0) {
      res.send(result.rows[0]);
    } else {
      res
        .status(404)
        .send({ message: "No se encontró ningún café con ese id" });
    }
  } catch (err) {
    res.status(500).send(err);
  }
});

// Ruta DELETE /cafes/:id
app.delete("/cafes/:id", async (req, res) => {
  const { id } = req.params;
  const jwt = req.header("Authorization");

  if (!jwt) {
    return res
      .status(400)
      .send({ message: "No recibió ningún token en las cabeceras" });
  }

  try {
    const result = await pool.query(
      "DELETE FROM cafes WHERE id = $1 RETURNING *",
      [id]
    );
    if (result.rows.length > 0) {
      res.send({ message: "Café eliminado correctamente" });
    } else {
      res
        .status(404)
        .send({ message: "No se encontró ningún cafe con ese id" });
    }
  } catch (err) {
    res.status(500).send(err);
  }
});

// Manejo de rutas no existentes
app.use("*", (req, res) => {
  res.status(404).send({ message: "La ruta que intenta consultar no existe" });
});

// Iniciar el servidor si el archivo no es importado en un test
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Servidor Activo en el puerto ${PORT}`);
  });
}

module.exports = app;
