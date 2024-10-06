import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import pkg from "pg";
import cors from "cors"; // Importar cors

const { Pool } = pkg;

// Configuración directa de la base de datos y la clave JWT
const dbUser = "williamscamacaro"; // Tu usuario de PostgreSQL
const dbPassword = "tu_contraseña"; // Contraseña de PostgreSQL
const dbHost = "localhost";
const dbDatabase = "softjobs";
const dbPort = 5432;
const jwtSecret = "mi_secret_para_jwt"; // Llave secreta para JWT

const app = express();
app.use(cors({ origin: "http://localhost:5173" })); // Habilitar CORS para solicitudes desde localhost:5173
app.use(express.json());

// Configuración de la base de datos
const pool = new Pool({
  user: dbUser,
  host: dbHost,
  database: dbDatabase,
  password: dbPassword,
  port: dbPort,
});

// Middleware para verificar autenticación JWT
const authMiddleware = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  console.log("Verificando token:", authHeader);
  if (!authHeader)
    return res.status(401).json({ error: "Token no proporcionado" });

  // Si el encabezado empieza con "Bearer ", extraer el token removiendo el prefijo
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7, authHeader.length)
    : authHeader;

  try {
    const decoded = jwt.verify(token, jwtSecret);
    console.log("Token válido, usuario decodificado:", decoded);
    req.user = decoded;
    next();
  } catch (error) {
    console.error("Token inválido:", error);
    res.status(401).json({ error: "Token inválido o expirado" });
  }
};

// Ruta para registrar un nuevo usuario
app.post("/usuarios", async (req, res) => {
  console.log("Solicitud para registrar usuario recibida con datos:", req.body);
  const { email, password, rol, lenguage } = req.body;

  try {
    if (!email || !password) {
      console.error("Error: Faltan email o contraseña.");
      return res
        .status(400)
        .json({ error: "El email y la contraseña son obligatorios" });
    }

    // Verificar si el usuario ya existe
    const userExists = await pool.query(
      "SELECT * FROM usuarios WHERE email = $1",
      [email]
    );
    console.log("Resultado de búsqueda de usuario:", userExists.rows);
    if (userExists.rows.length > 0) {
      console.error("Error: El usuario ya está registrado.");
      return res.status(400).json({ error: "El usuario ya está registrado" });
    }

    // Encriptar la contraseña y guardar el usuario
    const hashedPassword = await bcrypt.hash(password, 10);
    const query = `INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4) RETURNING *`;
    const values = [email, hashedPassword, rol, lenguage];
    const newUser = await pool.query(query, values);
    console.log("Usuario registrado exitosamente:", newUser.rows[0]);

    res.status(201).json({
      message: "Usuario registrado exitosamente",
      user: newUser.rows[0],
    });
  } catch (error) {
    console.error("Error al registrar el usuario:", error);
    res.status(500).json({ error: "Ocurrió un error al registrar el usuario" });
  }
});

// Ruta para iniciar sesión y obtener un token
app.post("/login", async (req, res) => {
  console.log("Solicitud de inicio de sesión recibida con datos:", req.body);
  const { email, password } = req.body;

  try {
    // Verificar si el usuario existe
    const result = await pool.query("SELECT * FROM usuarios WHERE email = $1", [
      email,
    ]);
    console.log("Resultado de búsqueda de usuario en login:", result.rows);
    if (result.rows.length === 0) {
      console.error("Error: Usuario no encontrado.");
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    const user = result.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.error("Error: Contraseña incorrecta.");
      return res.status(401).json({ error: "Contraseña incorrecta" });
    }

    // Crear un token JWT
    const token = jwt.sign({ email: user.email }, jwtSecret, {
      expiresIn: "1h",
    });
    console.log("Token generado:", token);
    res.status(200).json({ token });
  } catch (error) {
    console.error("Error al iniciar sesión:", error);
    res.status(500).json({ error: "Ocurrió un error al iniciar sesión" });
  }
});

// Ruta protegida para obtener datos del usuario
app.get("/usuarios", authMiddleware, async (req, res) => {
  console.log(
    "Solicitud para obtener datos de usuario. Usuario autenticado:",
    req.user
  );
  const { email } = req.user;

  try {
    const result = await pool.query(
      "SELECT id, email, rol, lenguage FROM usuarios WHERE email = $1",
      [email]
    );
    console.log("Resultado de búsqueda de perfil de usuario:", result.rows);
    if (result.rows.length === 0) {
      console.error("Error: Usuario no encontrado.");
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    res.status(200).json({ user: result.rows[0] });
  } catch (error) {
    console.error("Error al obtener el perfil del usuario:", error);
    res
      .status(500)
      .json({ error: "Ocurrió un error al obtener el perfil del usuario" });
  }
});

// Configurar el puerto del servidor
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Servidor escuchando en el puerto ${PORT}`);
});
