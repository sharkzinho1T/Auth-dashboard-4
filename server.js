import express        from 'express'
import session        from 'express-session'
import MemoryStore    from 'memorystore'
import { fileURLToPath } from 'url'
import { dirname, join }  from 'path'
import { randomUUID }     from 'crypto'
import { getDb, makeDb }  from './db.js'

const SessionStore = MemoryStore(session)

const __filename = fileURLToPath(import.meta.url)
const __dirname  = dirname(__filename)

const PORT             = Number(process.env.PORT || 3000)
const BOT_TOKEN        = process.env.BOT_TOKEN
const CLIENT_ID        = process.env.CLIENT_ID
const CLIENT_SECRET    = process.env.CLIENT_SECRET
const GUILD_ID         = process.env.GUILD_ID
const REDIRECT_URI     = process.env.REDIRECT_URI
const SESSION_SECRET   = process.env.SESSION_SECRET || 'fallback-dev-secret'
const DASHBOARD_PASS   = process.env.DASHBOARD_PASS
const HEARTBEAT_SECRET = process.env.HEARTBEAT_SECRET

if (!BOT_TOKEN || !CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI || !DASHBOARD_PASS) {
  console.error('[ORION] Variáveis faltando: BOT_TOKEN, CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, DASHBOARD_PASS')
  process.exit(1)
}

const DISCORD_API = 'https://discord.com/api/v10'
const OAUTH2_URL  = 'https://discord.com/oauth2/authorize'
const TOKEN_URL   = `${DISCORD_API}/oauth2/token`
const SCOPES      = 'identify guilds.join'

const app = express()

// Railway termina SSL no proxy — sem isso o req.secure nunca é true
// e o cookie de sessão não salva, causando redirect loop
app.set('trust proxy', 1)

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(express.static(join(__dirname, 'public')))

app.use(session({
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: new SessionStore({ checkPeriod: 1000 * 60 * 60 }),
  cookie: {
    maxAge:   1000 * 60 * 60 * 8,
    httpOnly: true,
    sameSite: 'lax',
    secure:   process.env.NODE_ENV === 'production'
  }
}))

/* ── BOT STATUS ─────────────────────────────── */

let botStatus = {
  online: false, username: null, id: null,
  guilds: 0, members: 0, guildList: [],
  ping: 0, uptime: 0, lastHeartbeat: null
}

/* ── MIDDLEWARE ─────────────────────────────── */

function requireAuth(req, res, next) {
  if (req.session?.authed) return next()
  res.status(401).json({ error: 'Não autenticado' })
}

function requireHeartbeatAuth(req, res, next) {
  if (!HEARTBEAT_SECRET) return next()
  if (req.headers['x-heartbeat-secret'] !== HEARTBEAT_SECRET)
    return res.status(403).json({ error: 'Forbidden' })
  next()
}

/* ── DISCORD OAUTH ──────────────────────────── */

async function exchangeCode(code) {
  const body = new URLSearchParams({
    client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
    grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI
  })
  const r    = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  })
  const data = await r.json()
  if (!r.ok) throw new Error(`Token: ${JSON.stringify(data)}`)
  return data
}

async function refreshAccessToken(refreshToken) {
  if (!refreshToken) throw new Error('Refresh token ausente')
  const body = new URLSearchParams({
    client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
    grant_type: 'refresh_token', refresh_token: refreshToken
  })
  const r    = await fetch(TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString()
  })
  const data = await r.json()
  if (!r.ok) throw new Error(`RefreshToken: ${JSON.stringify(data)}`)
  return data
}

async function fetchDiscordUser(accessToken) {
  const r    = await fetch(`${DISCORD_API}/users/@me`, {
    headers: { Authorization: `Bearer ${accessToken}` }
  })
  const data = await r.json()
  if (!r.ok) throw new Error(`User: ${JSON.stringify(data)}`)
  return data
}

/* ── BOOT ───────────────────────────────────── */

async function boot() {
  const rawDb = await getDb()
  const db    = makeDb(rawDb)

  /* ── OAUTH ROUTES ─────────────────────────── */

  app.get('/auth', (req, res) => {
    const linkId = req.query.link || 'default'
    const link   = db.prepare('SELECT id FROM auth_links WHERE id = ?').get(linkId)
    if (link) db.prepare('UPDATE auth_links SET clicks = COALESCE(clicks,0)+1 WHERE id = ?').run(linkId)
    const params = new URLSearchParams({
      client_id: CLIENT_ID, redirect_uri: REDIRECT_URI,
      response_type: 'code', scope: SCOPES, state: linkId
    })
    res.redirect(`${OAUTH2_URL}?${params}`)
  })

  app.get('/callback', async (req, res) => {
    const { code, state: linkId, error } = req.query
    if (error || !code) return res.redirect('/canceled.html')
    try {
      const tokens   = await exchangeCode(code)
      const user     = await fetchDiscordUser(tokens.access_token)
      const existing = db.prepare('SELECT id FROM users WHERE id = ?').get(user.id)
      if (existing) {
        db.prepare(`UPDATE users SET username=?,avatar=?,access_token=?,refresh_token=?,link_id=? WHERE id=?`)
          .run(user.username, user.avatar ?? null, tokens.access_token, tokens.refresh_token ?? null, linkId ?? 'default', user.id)
      } else {
        db.prepare(`INSERT INTO users (id,username,avatar,access_token,refresh_token,link_id,guild_id) VALUES (?,?,?,?,?,?,?)`)
          .run(user.id, user.username, user.avatar ?? null, tokens.access_token, tokens.refresh_token ?? null, linkId ?? 'default', null)
      }
      console.log(`[Orion] ✓ ${user.username} autenticado`)
      res.redirect('/success.html')
    } catch (err) {
      console.error('[Orion] Callback:', err.message)
      res.redirect('/error.html')
    }
  })

  /* ── DASHBOARD LOGIN ──────────────────────── */

  app.post('/api/login', (req, res) => {
    if (typeof req.body.password === 'string' && req.body.password === DASHBOARD_PASS) {
      req.session.authed = true
      return res.json({ ok: true })
    }
    res.status(401).json({ error: 'Senha incorreta' })
  })

  app.post('/api/logout', (req, res) => {
    req.session.destroy(() => res.json({ ok: true }))
  })

  app.get('/api/me', requireAuth, (req, res) => {
    res.json({ authenticated: true })
  })

  /* ── USERS ────────────────────────────────── */

  app.get('/api/users', requireAuth, (req, res) => {
    res.json(db.prepare(
      'SELECT id,username,avatar,link_id,guild_id,joined_at FROM users ORDER BY joined_at DESC'
    ).all())
  })

  app.post('/api/users/:id/refresh', requireAuth, async (req, res) => {
    try {
      const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id)
      if (!user)               return res.status(404).json({ error: 'Usuário não encontrado' })
      if (!user.refresh_token) return res.status(400).json({ error: 'Refresh token ausente' })
      const tokens = await refreshAccessToken(user.refresh_token)
      db.prepare('UPDATE users SET access_token=?,refresh_token=? WHERE id=?')
        .run(tokens.access_token, tokens.refresh_token ?? user.refresh_token, user.id)
      res.json({ ok: true })
    } catch {
      res.status(400).json({ error: 'Não foi possível renovar o token' })
    }
  })

  /* ── LINKS ────────────────────────────────── */

  app.get('/api/links', requireAuth, (req, res) => {
    res.json(db.prepare(
      'SELECT id,label,source_guild,clicks,created_at FROM auth_links ORDER BY created_at DESC'
    ).all())
  })

  app.get('/api/links/count', requireHeartbeatAuth, (req, res) => {
    const row = db.prepare('SELECT COUNT(*) AS count FROM auth_links').get()
    res.json({ count: row?.count ?? 0 })
  })

  app.post('/api/links', requireAuth, (req, res) => {
    const { label, source_guild } = req.body
    const id    = randomUUID().replaceAll('-', '').slice(0, 8)
    const final = typeof label === 'string' && label.trim() ? label.trim() : 'Link sem nome'
    db.prepare('INSERT INTO auth_links (id,label,source_guild) VALUES (?,?,?)').run(id, final, source_guild || null)
    const base = REDIRECT_URI.replace(/\/callback\/?$/, '')
    res.json({ id, url: `${base}/auth?link=${id}` })
  })

  /* ── SEND LINK ────────────────────────────── */

  app.post('/api/send-link', requireAuth, async (req, res) => {
    try {
      const { link_id, webhook_url, message } = req.body || {}
      if (!link_id)     return res.status(400).json({ error: 'Link não informado' })
      if (!webhook_url) return res.status(400).json({ error: 'Webhook não informado' })
      const link = db.prepare('SELECT id,label FROM auth_links WHERE id = ?').get(link_id)
      if (!link)  return res.status(404).json({ error: 'Link não encontrado' })
      const base    = REDIRECT_URI.replace(/\/callback\/?$/, '')
      const authUrl = `${base}/auth?link=${encodeURIComponent(link.id)}`
      const custom  = typeof message === 'string' ? message.trim() : ''
      const content = custom
        ? `${custom}\n\n🔗 **Link de autenticação:**\n${authUrl}`
        : `🔗 **Link de autenticação:**\n${authUrl}`
      const r = await fetch(webhook_url.trim(), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content })
      })
      if (!r.ok) return res.status(502).json({ error: `Webhook retornou HTTP ${r.status}` })
      console.log(`[Orion] ✓ Link enviado | ${link.id}`)
      res.json({ ok: true, url: authUrl })
    } catch (err) {
      res.status(500).json({ error: 'Falha ao enviar o link' })
    }
  })

  /* ── PULL ─────────────────────────────────── */

  app.post('/api/pull', requireAuth, async (req, res) => {
    try {
      const { target_guild_id, link_id } = req.body || {}
      if (!target_guild_id) return res.status(400).json({ error: 'Servidor de destino não informado' })
      const users = link_id
        ? db.prepare('SELECT id,username,access_token,refresh_token FROM users WHERE link_id=? ORDER BY joined_at DESC').all(link_id)
        : db.prepare('SELECT id,username,access_token,refresh_token FROM users ORDER BY joined_at DESC').all()
      const results = []
      for (const user of users) {
        try {
          if (!user.access_token) {
            results.push({ id: user.id, username: user.username, status: 'error', error: 'Token OAuth ausente' })
            continue
          }
          const r = await fetch(
            `${DISCORD_API}/guilds/${encodeURIComponent(target_guild_id)}/members/${encodeURIComponent(user.id)}`,
            {
              method: 'PUT',
              headers: { Authorization: `Bot ${BOT_TOKEN}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({ access_token: user.access_token })
            }
          )
          if (r.status === 204) {
            results.push({ id: user.id, username: user.username, status: 'already' })
          } else if (r.ok) {
            results.push({ id: user.id, username: user.username, status: 'joined' })
          } else {
            const data = await r.json().catch(() => ({}))
            results.push({ id: user.id, username: user.username, status: 'error', error: data.message || `HTTP ${r.status}` })
          }
        } catch (err) {
          results.push({ id: user.id, username: user.username, status: 'error', error: err.message })
        }
      }
      const summary = {
        total:   results.length,
        joined:  results.filter(x => x.status === 'joined').length,
        already: results.filter(x => x.status === 'already').length,
        errors:  results.filter(x => x.status === 'error').length
      }
      res.json({ ok: true, results, summary })
    } catch (err) {
      res.status(500).json({ error: 'Erro interno no pull' })
    }
  })

  /* ── SERVERS ──────────────────────────────── */

  app.get('/api/servers', requireAuth, (req, res) => {
    if (botStatus.online && Array.isArray(botStatus.guildList))
      return res.json(botStatus.guildList)
    res.json(db.prepare('SELECT id,name,icon,added_at FROM servers ORDER BY added_at DESC').all())
  })

  /* ── BOT HEARTBEAT ────────────────────────── */

  app.post('/api/bot/heartbeat', requireHeartbeatAuth, (req, res) => {
    const b  = req.body || {}
    botStatus = {
      online:        b.online === true,
      username:      b.username  ?? null,
      id:            b.id        ?? null,
      guilds:        Number(b.guilds  || 0),
      members:       Number(b.members || 0),
      guildList:     Array.isArray(b.guildList) ? b.guildList : [],
      ping:          Number(b.ping   ?? 0),
      uptime:        Number(b.uptime || 0),
      lastHeartbeat: Date.now()
    }
    res.json({ ok: true })
  })

  app.get('/api/bot/status', requireAuth, (req, res) => {
    const age    = botStatus.lastHeartbeat ? Date.now() - botStatus.lastHeartbeat : Infinity
    const online = botStatus.online && age < 30000
    res.json({ ...botStatus, online })
  })

  app.get('/ping', (req, res) => res.json({ status: 'ok', version: 'Orion V2' }))
  app.get('/', (req, res) => res.redirect('/dash/'))
  app.get('/dashboard', (req, res) => res.redirect('/dash/'))
  app.get('/dash', (req, res) => res.redirect('/dash/'))
  app.get('/dash/', (req, res) => {
    res.sendFile(join(__dirname, 'public', 'dash', 'index.html'))
  })

  app.use((err, req, res, next) => {
    console.error('[Orion] Express:', err)
    if (res.headersSent) return next(err)
    res.status(500).json({ error: 'Erro interno do servidor' })
  })

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`
  ╔══════════════════════════════════════╗
  ║        Orion V2 — Online             ║
  ║  Porta    : ${PORT}                     ║
  ║  Dashboard: /dash/                   ║
  ╚══════════════════════════════════════╝
    `)
  })
}

boot().catch(err => {
  console.error('[ORION] Boot falhou:', err)
  process.exit(1)
})
