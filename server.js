const express = require("express");
const next = require("next");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const db = require("./db");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

const dev = process.env.NODE_ENV !== "production";
const app = next({ dev });
const handle = app.getRequestHandler();

const expressApp = express();

function verificaToken(req, res, next) {
  const token = req.cookies.token;
  if (!token) return res.status(401).send("Token mancante");
  try {
    const payload = jwt.verify(token, "CHIAVE_SUPERSEGRETA");
    req.utente = payload;
    next();
  } catch (err) {
    return res.status(401).send("Token invalido");
  }
}

app.prepare().then(() => {
  expressApp.use(cookieParser());
  expressApp.use(cors({
    origin: "http://localhost:4000",
    credentials: true
  }));
  expressApp.use(express.json());

  // 🔐 ROTTE AUTENTICAZIONE
  expressApp.post("/login", (req, res) => {
    const { username, password } = req.body;

    db.query("SELECT * FROM utenti WHERE username = ?", [username], async (err, results) => {
      if (err) return res.status(500).send("Errore interno");
      if (results.length === 0) return res.status(401).send("Utente non trovato");

      const utente = results[0];
      const match = await bcrypt.compare(password, utente.password_hash);
      if (!match) return res.status(401).send("Password errata");

      const token = jwt.sign({
        id: utente.id,
        username: utente.username,
        ruolo: utente.ruolo
      }, "CHIAVE_SUPERSEGRETA", { expiresIn: "2d" });

      res.cookie("token", token, {
        httpOnly: true,
        secure: false,
        sameSite: "lax",
        path: "/",
        maxAge: 2 * 24 * 60 * 60 * 1000
      });

      res.send({ successo: true, ruolo: utente.ruolo });
    });
  });

  expressApp.get("/me", verificaToken, (req, res) => {
    res.send(req.utente);
  });

  // 📦 ROTTE AGGIUNTIVE QUI (es. /prodotti, /clienti, /ordini, ecc.)

  // ✅ NEXT HANDLER
  expressApp.all("*", (req, res) => {
    return handle(req, res);
  });

  // ▶️ AVVIO SERVER
  expressApp.listen(4000, () => {
    console.log("✅ App avviata su http://localhost:4000");
  });
});