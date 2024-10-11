const request = require("supertest");
const server = require("../index");

let app;

beforeAll((done) => {
  app = server.listen(0, () => {
    console.log("Servidor de prueba iniciado");
    done();
  });
});

afterAll((done) => {
  app.close(done); // Cerramos el servidor después de los tests
});

describe("Operaciones CRUD de cafes", () => {
  it("GET /cafes devuelve un status code 200 y un arreglo con al menos un objeto", async () => {
    const response = await request(app).get("/cafes").send();
    expect(response.statusCode).toBe(200);
    expect(response.body).toBeInstanceOf(Array);
    expect(response.body.length).toBeGreaterThan(0);
  });

  it("DELETE /cafes/:id devuelve un status code 404 si el café no existe", async () => {
    const fakeId = 999;
    const response = await request(app)
      .delete(`/cafes/${fakeId}`)
      .set("Authorization", "token")
      .send();
    expect(response.statusCode).toBe(404);
  });

  it("POST /cafes agrega un nuevo café y devuelve un status code 201", async () => {
    const newCafe = { nombre: "Latte" };
    const response = await request(app).post("/cafes").send(newCafe);
    expect(response.statusCode).toBe(201);
    expect(response.body.nombre).toBe("Latte");
  });

  it("PUT /cafes/:id devuelve un status code 400 si los IDs no coinciden", async () => {
    const updatedCafe = { id: 2, nombre: "Latte" };
    const response = await request(app).put("/cafes/3").send(updatedCafe);
    expect(response.statusCode).toBe(400);
  });
});
