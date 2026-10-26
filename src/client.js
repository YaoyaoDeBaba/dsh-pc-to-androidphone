/* 大肥鱼远控 —— 客户端
 *
 * 协议：dsh-rc/1（DSH Remote Control wire protocol），端到端加密（XSalsa20-Poly1305）。
 * 加密/哈希用官方同款实现（tweetnacl / js-sha512），KDF 严格按 SPEC 契约 B4-B6。
 */
import nacl from 'tweetnacl'
import sha512Module from 'js-sha512'

// js-sha512 是 CJS，不同打包器对具名导入的处理不一致；这里用默认导入再取方法，最稳。
const sha512Fn = typeof sha512Module === 'function' ? sha512Module : sha512Module.sha512

/* ================= 常量 ================= */
const PROTOCOL_VERSION = 1
const KDF_NS = 'dsh-rc/v1'
const NONCE_NS = 'dsh-rc/v1/nonce'
const UNIT = 0x1f
const DEFAULT_RELAY = 'wss://drc.provid.cc/v05'

/* ================= 二进制工具 ================= */
const te = new TextEncoder()
const td = new TextDecoder()

function concatBytes(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0)
  const out = new Uint8Array(total)
  let at = 0
  for (const a of arrs) { out.set(a, at); at += a.length }
  return out
}

function b64e(bytes) {
  let s = ''
  const CH = 0x8000
  for (let i = 0; i < bytes.length; i += CH) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + CH))
  }
  return btoa(s)
}

function b64d(str) {
  const bin = atob(str)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/* ================= SHA-512 / KDF（契约 B4-B6） ================= */
function sha512Bytes(bytes) {
  // 传 number[] 是最兼容的调用方式（库对 TypedArray 的支持因版本而异）。
  return Uint8Array.from(sha512Fn.array(Array.from(bytes)))
}

/** SHA-512(p0‖0x1f‖p1‖0x1f‖…‖pn‖0x1f)[0..32] —— 最后也要补分隔符 */
function kdfHash(parts) {
  const chunks = []
  for (const p of parts) {
    chunks.push(typeof p === 'string' ? te.encode(p) : p)
    chunks.push(Uint8Array.of(UNIT))
  }
  return sha512Bytes(concatBytes(...chunks)).subarray(0, 32)
}

function deriveKey(pskBytes, dir, convId) {
  return kdfHash([KDF_NS, dir, convId, pskBytes])
}

function noncePrefix(pskBytes, convId, installId) {
  return kdfHash([NONCE_NS, installId, convId, pskBytes]).subarray(0, 16)
}

function counterNonce(prefix, counter) {
  const high = Math.floor(counter / 0x100000000)
  const low = counter >>> 0
  return concatBytes(prefix, Uint8Array.of(
    (high >>> 24) & 0xff, (high >>> 16) & 0xff, (high >>> 8) & 0xff, high & 0xff,
    (low >>> 24) & 0xff, (low >>> 16) & 0xff, (low >>> 8) & 0xff, low & 0xff
  ))
}

/* ================= 密封记录（契约 B1-B3） ================= */
function seal(key, payload, nonce) {
  const box = nacl.secretbox(te.encode(JSON.stringify(payload)), nonce, key)
  return { ciphertext: b64e(concatBytes(nonce, box)) }
}

function openRecord(key, record) {
  try {
    const ct = record && record.ciphertext
    if (typeof ct !== 'string') return null
    const merged = b64d(ct)
    if (merged.length < 40) return null
    const nonce = merged.subarray(0, 24)
    const box = merged.subarray(24)
    const opened = nacl.secretbox.open(box, nonce, key)
    if (!opened) return null
    return JSON.parse(td.decode(opened))
  } catch (_) { return null }
}

/* ================= 状态 ================= */
const S = {
  ws: null,
  relay: localStorage.getItem('drc.relay') || DEFAULT_RELAY,
  clientId: localStorage.getItem('drc.clientId') || '',
  pendingCode: '',
  keypair: null,
  convId: '',
  pskBytes: null,
  kC2H: null,
  kH2C: null,
  noncePre: null,
  outSeq: 1,
  cmdSeq: 0,
  sessions: [],
  current: null,
  msgs: [],
  running: false,
  paired: false,
}

/* ================= UI ================= */
const $ = (id) => document.getElementById(id)
const el = {
  status: null, pairCard: null, listCard: null, chatCard: null,
  pairCode: null, connectBtn: null, relayUrl: null, saveRelayBtn: null,
  sessions: null, refreshBtn: null, messages: null, msgInput: null, sendBtn: null,
  log: null, clearLog: null, chatTitle: null,
}

function initEls() {
  for (const k of Object.keys(el)) el[k] = $(k)
}

function setStatus(text, color) {
  if (!el.status) return
  el.status.textContent = text
  el.status.style.color = color || '#8a8aa0'
}

const logLines = []
function log(...args) {
  const line = args.map(a => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ')
  logLines.push(line)
  if (logLines.length > 300) logLines.shift()
  if (el.log) {
    el.log.textContent = logLines.join('\n')
    el.log.scrollTop = el.log.scrollHeight
  }
}

/* ================= 渲染 ================= */
function renderSessions() {
  if (!el.sessions) return
  el.sessions.innerHTML = ''
  if (!S.sessions.length) {
    const d = document.createElement('div')
    d.className = 'muted'
    d.textContent = '还没有会话（点刷新试试）'
    el.sessions.appendChild(d)
    return
  }
  S.sessions.forEach((s, i) => {
    const item = s.session ?? s
    const id = item.sessionId || item.id || item.convId || ''
    const title = item.title || item.name || item.label || id || ('会话 ' + (i + 1))
    const btn = document.createElement('button')
    btn.className = 'session' + (S.current === id ? ' active' : '')
    btn.textContent = title
    btn.onclick = () => openSession(id, title)
    el.sessions.appendChild(btn)
  })
}

function renderMessages() {
  if (!el.messages) return
  el.messages.innerHTML = ''
  for (const m of S.msgs) {
    const d = document.createElement('div')
    d.className = 'msg ' + (m.role === 'me' ? 'me' : 'ai')
    d.textContent = m.text
    el.messages.appendChild(d)
  }
  el.messages.scrollTop = el.messages.scrollHeight
}

function showChat(on) {
  if (el.chatCard) el.chatCard.hidden = !on
}

function showList(on) {
  if (el.listCard) el.listCard.hidden = !on
}

/* ================= 消息事件归约（实时 + 历史共用） ================= */
function applyEvent(p) {
  if (!p || typeof p !== 'object') return
  const t = p.t || p.type
  switch (t) {
    case 'ev.session_changed':
      S.sessions = Array.isArray(p.sessions) ? p.sessions : []
      renderSessions()
      break
    case 'ev.message_delta': {
      const mid = p.messageId || p.id || 'x'
      let m = S.msgs.find(x => x.id === mid)
      if (!m) { m = { id: mid, role: 'ai', text: '' }; S.msgs.push(m) }
      if (typeof p.delta === 'string') m.text += p.delta
      renderMessages()
      break
    }
    case 'ev.session_history': {
      if (!S.historyLoaded) {
        S.msgs = []
        S.historyLoaded = true
      }
      const items = Array.isArray(p.items) ? p.items : []
      for (const it of items) applyEvent(it)
      renderMessages()
      break
    }
    case 'ev.run_state':
      S.running = p.state === 'running'
      setStatus(S.running ? '运行中…' : '空闲', S.running ? '#3ecf8e' : '#8a8aa0')
      break
    case 'ev.result':
      log('[result]', p.ok === false ? 'FAIL' : 'ok', p.message || '')
      break
    default:
      log('[ev]', t, JSON.stringify(p).slice(0, 300))
  }
}

/* ================= 命令 ================= */
function nextCmdId() {
  S.cmdSeq += 1
  return 'cmd_' + Date.now().toString(36) + '_' + S.cmdSeq
}

function sendSealed(payload) {
  if (!S.kC2H) { log('还没配对，发不了'); return }
  const nonce = counterNonce(S.noncePre, S.outSeq)
  S.outSeq += 1
  const rec = seal(S.kC2H, payload, nonce)
  const frame = { t: 'enc', sessionId: S.convId, seq: S.outSeq - 1, ciphertext: rec.ciphertext }
  sendRaw(frame)
}

function sendRaw(obj) {
  if (!S.ws || S.ws.readyState !== 1) return
  S.ws.send(JSON.stringify(obj))
}

function cmdListSessions() {
  sendSealed({ t: 'cmd.list_sessions', cmdId: nextCmdId() })
}

function openSession(id, title) {
  S.current = id
  S.msgs = []
  S.historyLoaded = false
  if (el.chatTitle) el.chatTitle.textContent = title || '对话'
  renderMessages()
  showChat(true)
  renderSessions()
  sendSealed({ t: 'cmd.session_history', cmdId: nextCmdId(), sessionId: id, limit: 50 })
}

function cmdSendPrompt() {
  const text = (el.msgInput?.value || '').trim()
  if (!text || !S.current) return
  el.msgInput.value = ''
  S.msgs.push({ id: 'me_' + Date.now(), role: 'me', text })
  renderMessages()
  sendSealed({ t: 'cmd.send_prompt', cmdId: nextCmdId(), sessionId: S.current, text })
}

/* ================= 连接 / 握手 / 配对 ================= */
function connect() {
  const code = (el.pairCode?.value || '').trim()
  if (!/^\d{6}$/.test(code)) { setStatus('配对码要 6 位数字', '#ff5c7a'); return }

  S.pendingCode = code
  S.paired = false
  S.convId = ''
  S.pskBytes = null
  S.kC2H = null
  S.kH2C = null
  S.keypair = nacl.box.keyPair()
  S.outSeq = 1

  setStatus('连接中…', '#5b8cff')
  log('连接 ' + S.relay)

  try { S.ws?.close() } catch (_) {}
  const ws = new WebSocket(S.relay)
  S.ws = ws

  ws.onopen = () => {
    log('已连上中继')
    setStatus('握手中…', '#5b8cff')
    const hello = { t: 'hello', role: 'client', protocol: PROTOCOL_VERSION }
    if (S.clientId) hello.clientId = S.clientId
    hello.clientMeta = { platform: 'android-webview', label: '大肥鱼远控' }
    sendRaw(hello)
  }

  ws.onmessage = (ev) => {
    let frame
    try { frame = JSON.parse(ev.data) } catch (_) { return }
    handleFrame(frame)
  }

  ws.onclose = () => {
    if (S.paired) setStatus('连接断开', '#ff5c7a')
    else setStatus('连接关闭', '#ff5c7a')
    log('连接关闭')
  }

  ws.onerror = () => { setStatus('连接出错', '#ff5c7a'); log('WebSocket 错误') }
}

function handleFrame(f) {
  const t = f.t
  if (t !== 'enc' && t !== 'enc-batch') log('[frame]', t, JSON.stringify(f).slice(0, 260))

  switch (t) {
    case 'hello-ok': {
      if (f.clientId) {
        S.clientId = f.clientId
        localStorage.setItem('drc.clientId', S.clientId)
      }
      if (typeof f.protocol === 'number' && f.protocol !== PROTOCOL_VERSION) {
        setStatus('协议版本不匹配 (' + f.protocol + ')', '#ff5c7a')
        return
      }
      log('hello-ok clientId=' + S.clientId)
      setStatus('配对中…', '#5b8cff')
      sendRaw({
        t: 'pair-begin-client',
        pairingToken: S.pendingCode,
        clientPub: b64e(S.keypair.publicKey),
      })
      break
    }

    case 'pair-fail': {
      const map = {
        invalid_or_expired: '配对码无效或已过期',
        already_used: '配对码已被使用',
        host_offline: '电脑端没在线',
        bad_token: '配对码不对',
      }
      setStatus(map[f.reason] || ('配对失败: ' + f.reason), '#ff5c7a')
      log('pair-fail', f.reason)
      break
    }

    case 'pair-grant': {
      const keys = Object.keys(f).join(',')
      const hostPubS = f.hostPub || f.hostPublicKey || f.pub || f.hostPk
      const nonceS = f.nonce || f.iv || f.n
      const wrappedS = f.wrappedPsk || f.psk || f.wrapped || f.ciphertext
      const short = (s) => (typeof s === 'string' ? s.slice(0, 12) + '…(' + s.length + ')' : String(s))
      log('[pair-grant] keys=' + keys)
      log('[pair-grant] hostPub=' + short(hostPubS) + ' nonce=' + short(nonceS) + ' wrapped=' + short(wrappedS))
      if (!hostPubS || !wrappedS) { log('pair-grant 字段认不出'); break }
      try {
        const shared = nacl.box.before(b64d(hostPubS), S.keypair.secretKey)
        // 官方方案（crypto/sas.ts）：包裹密钥 = SHA-512(shared ‖ "dsh-rc/psk-wrap")[0..32]
        const wrapKey = sha512Bytes(concatBytes(shared, te.encode('dsh-rc/psk-wrap'))).subarray(0, 32)
        // 6 位 SAS 比对码（给用户核对；不阻断流程）
        const s = sha512Bytes(concatBytes(shared, te.encode('dsh-rc/sas'))).subarray(0, 4)
        const v = ((s[0] << 24) | (s[1] << 16) | (s[2] << 8) | s[3]) >>> 0
        log('[pair-grant] SAS=' + String(v % 1000000).padStart(6, '0'))

        const wrappedBytes = b64d(wrappedS)
        const candidates = []
        const tryOpen = (key, ct) => {
          try {
            const r = nacl.secretbox.open(ct, b64d(nonceS), key)
            if (r) candidates.push(r)
          } catch (_) {}
        }
        // 方案 A（官方）：wrapKey + 独立 nonce
        if (nonceS) tryOpen(wrapKey, wrappedBytes)
        // 方案 B（兼容旧版）：直接拿 shared 当密钥
        if (nonceS) tryOpen(shared, wrappedBytes)
        // 方案 C：wrapped 自身就是 nonce(24)‖box（同 seal 的记录格式）
        if (wrappedBytes.length >= 40) {
          try {
            const r = nacl.secretbox.open(wrappedBytes.subarray(24), wrappedBytes.subarray(0, 24), wrapKey)
            if (r) candidates.push(r)
          } catch (_) {}
        }
        log('[pair-grant] 解出候选 ' + candidates.length + ' 个')
        if (!candidates.length) { setStatus('密钥解开失败', '#ff5c7a'); log('psk 解密失败'); break }
        let psk = null
        for (const raw of candidates) {
          let bytes = raw
          try {
            const txt = td.decode(raw)
            const t = txt.trim()
            if (t.startsWith('{')) {
              const obj = JSON.parse(t)
              const cand = obj.psk || obj.key || obj.wrappedPsk
              if (typeof cand === 'string') bytes = b64d(cand)
            } else if (bytes.length !== 16 && /^[A-Za-z0-9+/]+={0,2}$/.test(t)) {
              bytes = b64d(t)
            }
          } catch (_) {}
          if (bytes.length === 16) { psk = bytes; break }
        }
        if (!psk) { setStatus('PSK 格式不对', '#ff5c7a'); log('解开了但内容不是 16 字节'); break }
        S.pskBytes = psk
        log('拿到 PSK（16 字节）')
        if (f.sessionId) S.convId = f.sessionId
        tryFinishPairing()
      } catch (e) {
        log('pair-grant 异常', String(e))
      }
      break
    }

    case 'paired': {
      S.convId = f.sessionId || S.convId
      log('paired sessionId=' + S.convId + ' hostId=' + f.hostId)
      tryFinishPairing()
      break
    }

    case 'enc': {
      if (!S.kH2C) return
      const payload = openRecord(S.kH2C, f)
      if (!payload) { log('解不开一帧（密钥或格式不对）'); return }
      applyEvent(payload)
      break
    }

    case 'enc-batch': {
      if (!S.kH2C) return
      const items = Array.isArray(f.items) ? f.items : []
      for (const it of items) {
        const payload = openRecord(S.kH2C, it)
        if (payload) applyEvent(payload)
      }
      break
    }

    case 'error': {
      setStatus('中继错误: ' + (f.code || ''), '#ff5c7a')
      log('error', f.code, f.message || '')
      break
    }

    case 'pong':
      break

    default:
      log('[frame:other]', t)
  }
}

function tryFinishPairing() {
  if (S.paired) return
  if (!S.convId || !S.pskBytes) return
  S.paired = true
  S.kC2H = deriveKey(S.pskBytes, 'c2h', S.convId)
  S.kH2C = deriveKey(S.pskBytes, 'h2c', S.convId)
  S.noncePre = noncePrefix(S.pskBytes, S.convId, S.clientId || 'anon')
  S.outSeq = 1

  setStatus('已配对', '#3ecf8e')
  log('配对完成，开始拉会话')
  showList(true)
  showChat(false)
  cmdListSessions()
}

/* ================= 启动 ================= */
function boot() {
  initEls()

  if (el.relayUrl) {
    el.relayUrl.value = S.relay
    el.saveRelayBtn?.addEventListener('click', () => {
      const v = (el.relayUrl.value || '').trim()
      if (/^wss?:\/\//.test(v)) {
        S.relay = v
        localStorage.setItem('drc.relay', v)
        log('中继已保存: ' + v)
      } else {
        log('中继地址要以 ws:// 或 wss:// 开头')
      }
    })
  }

  el.connectBtn?.addEventListener('click', connect)
  el.pairCode?.addEventListener('keydown', (e) => { if (e.key === 'Enter') connect() })
  el.refreshBtn?.addEventListener('click', () => { if (S.paired) cmdListSessions() })
  el.sendBtn?.addEventListener('click', cmdSendPrompt)
  el.msgInput?.addEventListener('keydown', (e) => { if (e.key === 'Enter') cmdSendPrompt() })
  el.clearLog?.addEventListener('click', () => { logLines.length = 0; if (el.log) el.log.textContent = '' })

  setStatus('未连接')
  log('客户端已加载，中继: ' + S.relay)
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot)
} else {
  boot()
}
