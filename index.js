const express = require('express');
const cors = require('cors');
const app = express();
const db = require('./db');
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
require("dotenv").config();

function verificaToken(req, res, next) {
  console.log("\n💬 Cookie ricevuti:", req.cookies);
  const token = req.cookies.token;
  if (!token) return res.status(401).send("Token mancante");

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET || "CHIAVE_SUPERSEGRETA");
    req.utente = payload;
    next();
  } catch (err) {
    return res.status(401).send("Token invalido");
  }
}

app.use(express.json());
app.use(cookieParser());
app.use(cors({
  origin: "http://localhost:3000",
  credentials: true
}));

// --- ROTTE AUTENTICAZIONE ---
app.get('/me', verificaToken, (req, res) => {
  res.send(req.utente);
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.query("SELECT * FROM utenti WHERE username = ?", [username], async (err, results) => {
    if (err) return res.status(500).send("Errore interno");
    if (results.length === 0) return res.status(401).send("Utente non trovato");

    const utente = results[0];
    const match = await bcrypt.compare(password, utente.password_hash);

    if (!match) return res.status(401).send("Password errata");

    const token = jwt.sign(
      {
        id: utente.id,
        username: utente.username,
        ruolo: utente.ruolo
      },
      process.env.JWT_SECRET || "CHIAVE_SUPERSEGRETA",
      { expiresIn: "2d" }
    );

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

// --- GESTIONE UTENTI ---
app.get('/utenti', verificaToken, (req, res) => {
  db.query("SELECT id, username, ruolo FROM utenti", (err, results) => {
    if (err) return res.status(500).send("Errore DB");
    res.json(results);
  });
});

app.patch('/utenti/:id', verificaToken, (req, res) => {
  const id = req.params.id;
  const { ruolo } = req.body;

  db.query("UPDATE utenti SET ruolo = ? WHERE id = ?", [ruolo, id], (err) => {
    if (err) return res.status(500).send("Errore DB");
    res.send({ success: true });
  });
});

// --- ALTRE ROTTE (ESEMPIO) ---
app.get('/prodotti', (req, res) => {
  db.query('SELECT * FROM prodotti', (err, results) => {
    if (err) return res.status(500).send(err);
    res.json(results);
  });
});

app.get('/clienti', (req, res) => {
  db.query('SELECT * FROM clienti', (err, results) => {
    if (err) return res.status(500).send(err);
    res.json(results);
  });
});

app.post('/ordini', (req, res) => {
  const { id_cliente, righe, operatore } = req.body;
  const data_ordine = new Date().toISOString().split('T')[0];

  db.query(
    'INSERT INTO ordini (id_cliente, data_ordine, operatore) VALUES (?, ?, ?)',
    [id_cliente, data_ordine, operatore],
    (err, result) => {
      if (err) return res.status(500).send(err);
      const id_ordine = result.insertId;

      const valori = righe.map(r => [
        id_ordine,
        r.id_prodotto,
        r.quantita,
        r.peso_effettivo,
        false
      ]);

      db.query(
        'INSERT INTO dettagli_ordini (id_ordine, id_prodotto, quantita, peso_effettivo, preparato) VALUES ?',
        [valori],
        (err2) => {
          if (err2) return res.status(500).send(err2);
          res.send({ success: true });
        }
      );
    }
  );
});

app.post('/ordini-per-giorno', (req, res) => {
  const { data } = req.body;

  const query = `
  SELECT 
    d.id AS id_riga,
    o.id AS id_ordine,
    o.data_ordine,
    o.operatore,
    c.nome AS cliente,
    c.zona AS cliente_zona,
    p.nome AS prodotto,
    d.quantita,
    d.peso_effettivo,
    d.preparato
  FROM ordini o
  JOIN clienti c ON o.id_cliente = c.id
  JOIN dettagli_ordini d ON d.id_ordine = o.id
  JOIN prodotti p ON d.id_prodotto = p.id
  WHERE o.data_ordine = ?
  ORDER BY c.nome ASC, p.nome ASC
`;

  db.query(query, [data], (err, results) => {
    if (err) return res.status(500).send(err);
    res.json(results);
  });
});

app.get('/ordini', (req, res) => {
  const query = `
    SELECT o.id, o.data_ordine, o.stato, o.operatore, c.nome AS cliente, COUNT(d.id) AS num_prodotti
    FROM ordini o
    JOIN clienti c ON o.id_cliente = c.id
    LEFT JOIN dettagli_ordini d ON d.id_ordine = o.id
    GROUP BY o.id
  `;

  db.query(query, (err, results) => {
    if (err) return res.status(500).send(err);
    res.json(results);
  });
});

app.get('/ordini/:id', (req, res) => {
  const id = req.params.id;

  const queryOrdine = `
    SELECT o.id, o.data_ordine, o.stato, o.operatore, c.nome AS cliente
    FROM ordini o
    JOIN clienti c ON o.id_cliente = c.id
    WHERE o.id = ?
  `;

  const queryDettagli = `
    SELECT p.nome, d.quantita, d.peso_effettivo, d.preparato
    FROM dettagli_ordini d
    JOIN prodotti p ON d.id_prodotto = p.id
    WHERE d.id_ordine = ?
  `;

  db.query(queryOrdine, [id], (err, resultOrdine) => {
    if (err || resultOrdine.length === 0) return res.status(404).send({ errore: "Ordine non trovato" });

    db.query(queryDettagli, [id], (err2, resultProdotti) => {
      if (err2) return res.status(500).send(err2);

      res.send({
        ...resultOrdine[0],
        prodotti: resultProdotti
      });
    });
  });
});

app.patch('/dettagli-ordine/:id', (req, res) => {
  const id = req.params.id;
  const { peso_effettivo, preparato } = req.body;

  const query = `
    UPDATE dettagli_ordini
    SET peso_effettivo = ?, preparato = ?
    WHERE id = ?
  `;

  db.query(query, [peso_effettivo, preparato, id], (err) => {
    if (err) return res.status(500).send(err);
    res.send({ success: true });
  });
});

// --- IMPORTAZIONE PRODOTTI ---
app.post('/importa-prodotti', (req, res) => {
  const prodotti = req.body;
  if (!Array.isArray(prodotti)) return res.status(400).send("Formato non valido");

  const valori = prodotti.map(p => [
    p.codice, p.nome, p.categoria, p.prezzo, p.peso_variabile
  ]);

  const query = `
    INSERT INTO prodotti (codice, nome, categoria, prezzo, peso_variabile)
    VALUES ?
  `;

  db.query(query, [valori], (err) => {
    if (err) {
      console.error("Errore durante importazione prodotti:", err);
      return res.status(500).send("Errore DB");
    }
    res.send({ success: true });
  });
});

// --- IMPORTAZIONE CLIENTI ---
app.post('/importa-clienti', (req, res) => {
  const clienti = req.body;
  if (!Array.isArray(clienti)) return res.status(400).send("Formato non valido");

  const valori = clienti.map(c => [c.nome, c.zona]);

  const query = `
    INSERT INTO clienti (nome, zona)
    VALUES ?
  `;

  db.query(query, [valori], (err) => {
    if (err) {
      console.error("Errore durante importazione clienti:", err);
      return res.status(500).send("Errore DB");
    }
    res.send({ success: true });
  });
});

app.listen(4000, () => {
  console.log('✅ Server Backend attivo sulla porta 4000');
});
