const TokenHelper = require("../helpers/token.helper");

var auth = (req, res, next) => {
  const authorization = req.headers.authorization;
  if (!authorization || !authorization.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({
        result: "KO",
        msg: "Cabecera de autenticación tipo Bearer no encontrada [Authorization: Bearer jwtToken]",
      });
  }

  const queToken = authorization.split(" ")[1];

  //Comprobamos que el token no esté vacío
  if (!queToken) {
    return res.status(401).send({
      result: "KO",
      msg: "Token de acceso JWT no encontrado dentro de la cabecera [Authorization: Bearer jwtToken]",
    });
  }

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

// Exportar módulos

module.exports = {
  auth,
};
