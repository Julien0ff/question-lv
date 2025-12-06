require('dotenv').config();
const { Pool } = require('pg');
const pool = new Pool({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });
async function query(text, params) { const res = await pool.query(text, params); return res.rows; }
module.exports = { pool, query };
