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
const bcrypt = require("bcrypt");
const AuthMiddleware = require("./middlewares/auth.middleware");

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

app.get("/api/user", AuthMiddleware.auth, (req, res, next) => {
  db.user.find((err, coleccion) => {
    if (err) res.status(500).json({ result: "KO", msg: err });
    res.json(coleccion);
  });
});

app.get("/api/auth", AuthMiddleware.auth, (req, res, next) => {
  // Devolvemos sólo email y displayName (sin _id)
  db.user.find({}, { email: 1, displayName: 1, _id: 0 }, (err, coleccion) => {
    if (err) return res.status(500).json({ result: "KO", msg: err });
    res.json({ result: "OK", usuarios: coleccion });
  });
});

app.get("/api/user/:id", AuthMiddleware.auth, (req, res, next) => {
  const elementoId = req.params.id;
  db.user.findOne({ _id: elementoId }, (err, elementoRecuperado) => {
    if (err) return res.status(500).json({ result: "KO", msg: err });
    res.json(elementoRecuperado);
  });
});

app.get("/api/auth/me", AuthMiddleware.auth, (req, res, next) => {
  const elementoId = req.user.id;
  db.user.findOne({ _id: id(elementoId) }, (err, elementoRecuperado) => {
    if (err) return res.status(500).json({ result: "KO", msg: err });
    if (!elementoRecuperado)
      return res
        .status(404)
        .json({ result: "KO", msg: "Usuario no encontrado" });

    res.json({ result: "OK", usuario: elementoRecuperado });
  });
});

app.post("/api/auth/reg", (req, res, next) => {
  const { name, email, pass } = req.body;
  if (!name || !email || !pass) {
    return res
      .status(400)
      .json({ result: "KO", msg: "Faltan campos requeridos" });
  }
  db.user.findOne({ email }, (err, existingUser) => {
    if (err) return res.status(500).json({ result: "KO", msg: err });
    if (existingUser) {
      return res
        .status(400)
        .json({ result: "KO", msg: "El email ya está registrado" });
    }
    bcrypt.hash(pass, 10, (err, hashedPass) => {
      if (err) return res.status(500).json({ result: "KO", msg: err });
      const newUser = {
        displayName: name,
        email,
        password: hashedPass,
        signupDate: Math.floor(Date.now() / 1000),
        lastLogin: Math.floor(Date.now() / 1000),
      };
      db.user.save(newUser, (err, savedUser) => {
        if (err) return res.status(500).json({ result: "KO", msg: err });
        const token = TokenHelper.creaToken(savedUser);
        res.json({ result: "OK", token, usuario: savedUser });
      });
    });
  });
});

app.post("/api/auth/login", (req, res, next) => {
  const { email, pass } = req.body;
  if (!email || !pass) {
    return res.status(400).json({
      result: "KO",
      msg: "Debe suministrar un correo y una contraseña",
    });
  }
  db.user.findOne({ email }, (err, user) => {
    if (err) return res.status(500).json({ result: "KO", msg: err });
    if (!user) {
      return res.status(401).json({
        result: "KO",
        msg: "El usuario no está registrado o la contraseña no es correcta",
      });
    }
    bcrypt.compare(pass, user.password, (err, isMatch) => {
      if (err) return res.status(500).json({ result: "KO", msg: err });
      if (!isMatch) {
        return res.status(401).json({
          result: "KO",
          msg: "El usuario no está registrado o la contraseña no es correcta",
        });
      }
      user.lastLogin = Math.floor(Date.now() / 1000);
      db.user.update(
        { _id: user._id },
        { $set: { lastLogin: user.lastLogin } },
        (err) => {
          if (err) return res.status(500).json({ result: "KO", msg: err });
          const token = TokenHelper.creaToken(user);
          res.json({ result: "OK", token, usuario: user });
        },
      );
    });
  });
});

app.post("/api/user", AuthMiddleware.auth, (req, res, next) => {
  const nuevoElemento = req.body;
  db.user.save(nuevoElemento, (err, coleccionGuardada) => {
    if (err) res.status(500).json({ result: "KO", msg: err });
    res.json(coleccionGuardada);
  });
});

app.put("/api/user/:id", AuthMiddleware.auth, (req, res, next) => {
  const elementoId = req.params.id;
  const nuevosRegistros = req.body;
  db.user.update(
    { _id: elementoId },
    { $set: nuevosRegistros },
    { safe: true, multi: false },
    (err, result) => {
      if (err) res.status(500).json({ result: "KO", msg: err });
      res.json(result);
    },
  );
});

app.delete("/api/user/:id", AuthMiddleware.auth, (req, res, next) => {
  const elementoId = req.params.id;
  db.user.remove({ _id: elementoId }, (err, resultado) => {
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
