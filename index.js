"use strict";

// inportaciones
const config = require("./config");
const express = require("express");
const logger = require("morgan");
const mongojs = require("mongojs");
const cors = require("cors");
const fs = require("fs");
const https = require("https");
const helmet = require("helmet");
const TokenHelper = require("./helpers/token.helper");

// Declaraciones
const port = config.PORT;
const urlDB = config.DB;
const app = express();
const db = mongojs(urlDB); // Enlazamos con la DB
const id = mongojs.ObjectID; // Función para convertir un id textual en un objectID

// Declaraciones para CORS
var allowCrossTokenOrigin = (req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*"); // Permiso a cualquier URL. Mejor acotar
  return next();
};

var allowCrossTokenMethods = (req, res, next) => {
  res.header("Access-Control-Allow-Methods", "*"); // Mejor acotar (GET,PUT,POST,DELETE)
  return next();
};

var allowCrossTokenHeaders = (req, res, next) => {
  res.header("Access-Control-Allow-Headers", "*"); // Mejor acotar (Content-type)
  return next();
};

// middleware
var auth = (req, res, next) => {

  const queToken = req.headers.authorization.split(" ")[1];

  TokenHelper.decodificaToken(queToken).then(
    (userID) => {
      req.user = {
        token: queToken,
        id: userID,
      };
      return next(); // Pasamos el testigo al controlador de la ruta
    },
    (err) => {
      res.status(401);
      res.json({ result: "KO", msg: `No autorizado: ${err.msg}` });
    },
  );
};

// middlewares
app.use(logger("dev")); // probar con: tiny, short, dev, common, combined
app.use(express.urlencoded({ extended: false })); // parse application/x-www-form-urlencoded
app.use(express.json()); // parse application/json
app.use(cors()); // activamos CORS
app.use(allowCrossTokenOrigin); // configuramos origen permitido para CORS
app.use(allowCrossTokenMethods); // configuramos métodos permitidos para CORS
app.use(allowCrossTokenHeaders); // configuramos cabeceras permitidas para CORS
app.use(helmet());

// routes

app.get("/api/user", auth, (req, res, next) => {
  db.user.find((err, coleccion) => {
    if (err) res.status(500).json({ result: "KO", msg: err });
    res.json(coleccion);
  });
});

app.get("/api/user/:id", auth, (req, res, next) => {
  const elementoId = req.params.id;
  db.user.findOne({ _id: id(elementoId) }, (err, elementoRecuperado) => {
    if (err) res.status(500).json({ result: "KO", msg: err });
    res.json(elementoRecuperado);
  });
});

app.post("/api/user", auth, (req, res, next) => {
  const nuevoElemento = req.body;
  db.user.save(nuevoElemento, (err, coleccionGuardada) => {
    if (err) res.status(500).json({ result: "KO", msg: err });
    res.json(coleccionGuardada);
  });
});

app.put("/api/user/:id", auth, (req, res, next) => {
  const elementoId = req.params.id;
  const nuevosRegistros = req.body;
  db.user.update(
    { _id: id(elementoId) },
    { $set: nuevosRegistros },
    { safe: true, multi: false },
    (err, result) => {
      if (err) res.status(500).json({ result: "KO", msg: err });
      res.json(result);
    },
  );
});

app.delete("/api/user/:id", auth, (req, res, next) => {
  const elementoId = req.params.id;
  db.user.remove({ _id: id(elementoId) }, (err, resultado) => {
    if (err) res.status(500).json({ result: "KO", msg: err });
    res.json(resultado);
  });
});

// Iniciamos la aplicación
https
  .createServer(
    {
      cert: fs.readFileSync("./cert/cert.pem"),
      key: fs.readFileSync("./cert/key.pem"),
    },
    app,
  )
  .listen(config.PORT, function () {
    console.log(
      `API AUTH ejecutándose en https://localhost:${port}/api/{user|auth}/{id}`,
    );
  });
