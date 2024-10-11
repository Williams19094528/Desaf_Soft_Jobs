-- Crear la base de datos (si no existe)
CREATE DATABASE nanacao_db;

-- Conectar a la base de datos
\c nanacao_db;

-- Crear la tabla 'cafes'
CREATE TABLE cafes (
  id SERIAL PRIMARY KEY,
  nombre VARCHAR(100) NOT NULL
);

-- Insertar registros en la tabla 'cafes'
INSERT INTO cafes (nombre) VALUES 
('Cortado'),
('Americano'),
('Mocacino'),
('Cappuccino');
