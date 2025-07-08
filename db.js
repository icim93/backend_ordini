require("dotenv").config();
const mysql = require("mysql2");

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "ordini_azienda"
});

db.connect(err => {
  if (err) throw err;
  console.log("✅ Database connesso!");
});

module.exports = db;