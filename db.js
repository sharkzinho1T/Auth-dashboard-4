import { fileURLToPath } from 'url'
import { dirname, join }  from 'path'
import fs                 from 'fs'
import { createRequire }  from 'module'

const require    = createRequire(import.meta.url)
const initSqlJs  = require('sql.js')

const __filename = fileURLToPath(import.meta.url)
const __dirname  = dirname(__filename)

const DB_PATH = join(__dirname, 'orion.db')

/*
 * sql.js roda SQLite em WASM — zero compilação nativa.
 * O banco é um Buffer em memória, persistido em disco
 * a cada write. Railway tem filesystem efêmero, então
 * se precisar de persistência real, use Railway Volumes
 * ou troque pra PostgreSQL via @railway/postgres.
 */

let _db = null

function save() {
  const data = _db.export()
  fs.writeFileSync(DB_PATH, Buffer.from(data))
}

export async function getDb() {
  if (_db) return _db

  const SQL = await initSqlJs()

  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH)
    _db = new SQL.Database(fileBuffer)
  } else {
    _db = new SQL.Database()
  }

  _db.run(`PRAGMA journal_mode = WAL;`)
  _db.run(`PRAGMA foreign_keys = ON;`)

  _db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id            TEXT PRIMARY KEY,
      username      TEXT NOT NULL,
      avatar        TEXT,
      access_token  TEXT,
      refresh_token TEXT,
      link_id       TEXT DEFAULT 'default',
      guild_id      TEXT,
      joined_at     DATETIME DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS auth_links (
      id           TEXT PRIMARY KEY,
      label        TEXT NOT NULL DEFAULT 'Link sem nome',
      source_guild TEXT,
      clicks       INTEGER DEFAULT 0,
      created_at   DATETIME DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS servers (
      id       TEXT PRIMARY KEY,
      name     TEXT NOT NULL,
      icon     TEXT,
      added_at DATETIME DEFAULT (datetime('now'))
    );
  `)

  save()
  return _db
}

/*
 * Helpers que imitam a API do better-sqlite3
 * pra não ter que reescrever o server.js inteiro.
 * prepare(sql).get(params)  → primeira linha ou undefined
 * prepare(sql).all(params)  → array de rows
 * prepare(sql).run(params)  → void, salva em disco
 */
export function makeDb(db) {
  return {
    prepare(sql) {
      return {
        get(...params) {
          const stmt = db.prepare(sql)
          stmt.bind(params.flat())
          const row = stmt.step() ? stmt.getAsObject() : undefined
          stmt.free()
          return row
        },
        all(...params) {
          const stmt   = db.prepare(sql)
          stmt.bind(params.flat())
          const rows   = []
          while (stmt.step()) rows.push(stmt.getAsObject())
          stmt.free()
          return rows
        },
        run(...params) {
          db.run(sql, params.flat())
          save()
        }
      }
    },
    exec(sql) {
      db.run(sql)
      save()
    }
  }
}
