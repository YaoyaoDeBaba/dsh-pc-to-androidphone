/* 大肥鱼远控 —— 客户端
 *
 * 协议：dsh-rc/1（DSH Remote Control wire protocol），端到端加密（XSalsa20-Poly1305）。
 * 加密/哈希用官方同款实现（tweetnacl / js-sha512），KDF 严格按 SPEC 契约 B4-B6；
 * 配对用 X25519 + SAS（crypto/sas.ts 的 "dsh-rc/psk-wrap" 包裹）。
 */
import nacl from 'tweetnacl'
import sha512Module from 'js-sha512'

const sha512Fn = typeof sha512Module === 'function' ? sha512Module : sha512Module.sha512

/* ================= 常量 ================= */
const PROTOCOL_VERSION = 1
const KDF_NS = 'dsh-rc/v1'
const NONCE_NS = 'dsh-rc/v1/nonce'
const WRAP_LABEL = 'dsh-rc/psk-wrap'
const SAS_LABEL = 'dsh-rc/sas'
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
  return Uint8Array.from(sha512Fn.array(Array.from(bytes)))
}

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
    const opened = nacl.secretbox.open(merged.subarray(24), merged.subarray(0, 24), key)
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
  paired: false,
  view: 'pair',
  sessions: [],
  current: null,
  currentTitle: '',
  msgs: [],
  historyLoaded: false,
  cards: {},     // requestId -> { sessionId, kind:'perm'|'q', payload }
  qSel: {},      // requestId -> { questionId: [optionId] }
  running: {},   // dshSessionId -> boolean
  statusText: '未连接',
}

/* ================= DOM ================= */
const $ = (id) => document.getElementById(id)
const el = {}
function initEls() {
  const ids = ['status', 'title', 'backBtn', 'pairView', 'listView', 'chatView', 'logCard',
    'pairCode', 'connectBtn', 'relayUrl', 'saveRelayBtn', 'sessions', 'refreshBtn',
    'messages', 'msgInput', 'sendBtn', 'stopBtn', 'composer', 'log', 'clearLog', 'main']
  for (const k of ids) el[k] = $(k)
}

function setStatus(text, color) {
  S.statusText = text
  if (el.status) {
    el.status.textContent = text
    el.status.style.color = color || '#8a8aa0'
  }
}

const logLines = []
function log(...args) {
  const line = args.map(a => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ')
  logLines.push(line)
  if (logLines.length > 400) logLines.shift()
  if (el.log) {
    el.log.textContent = logLines.join('\n')
    el.log.scrollTop = el.log.scrollHeight
  }
}

/* ================= 视图切换 ================= */
function showView(name) {
  S.view = name
  el.pairView.hidden = name !== 'pair'
  el.listView.hidden = name !== 'list'
  el.chatView.hidden = name !== 'chat'
  el.logCard.hidden = name === 'chat'
  el.composer.hidden = name !== 'chat'
  el.backBtn.hidden = name !== 'chat'
  if (el.title) el.title.textContent = name === 'chat' ? (S.currentTitle || '对话') : '大肥鱼远控'
  if (name === 'chat' && el.main) el.main.scrollTop = el.main.scrollHeight
}

/* ================= 会话列表（含状态徽标） ================= */
function sessionState(s) {
  const id = s.id
  if (S.running[id]) return { cls: 'run', text: '运行中' }
  switch (s.state) {
    case 'running': return { cls: 'run', text: '运行中' }
    case 'awaiting-permission': return { cls: 'attn', text: '待审批' }
    case 'awaiting-answer': return { cls: 'attn', text: '待回答' }
    case 'detached': return { cls: '', text: '已脱离' }
    case 'archived': return { cls: '', text: '已归档' }
    default: return { cls: '', text: '空闲' }
  }
}

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
  for (const raw of S.sessions) {
    const s = raw.session ?? raw
    const id = s.id || s.sessionId || s.convId || ''
    const title = s.title || s.name || s.label || id || '会话'
    const st = sessionState(s)
    const btn = document.createElement('button')
    btn.className = 'session' + (S.current === id ? ' active' : '')
    const t = document.createElement('span'); t.className = 't'; t.textContent = title
    const b = document.createElement('span'); b.className = 'badge ' + st.cls; b.textContent = st.text
    btn.appendChild(t); btn.appendChild(b)
    btn.onclick = () => openSession(id, title)
    el.sessions.appendChild(btn)
  }
}

/* ================= 消息渲染 ================= */
function autoScroll() {
  if (el.main) el.main.scrollTop = el.main.scrollHeight
}

// 流式输出节流：一帧内多次 delta 只重绘一次，避免长回答卡顿
let rafPending = false
function scheduleRender() {
  if (rafPending) return
  rafPending = true
  requestAnimationFrame(() => { rafPending = false; renderMessages() })
}

function renderMessages() {
  if (!el.messages) return
  el.messages.innerHTML = ''
  for (const m of S.msgs) {
    const d = document.createElement('div')
    d.className = 'msg ' + (m.kind === 'tool' ? 'tool' : (m.role || 'assistant'))
    d.textContent = m.text
    el.messages.appendChild(d)
  }
  // 当前会话里还挂着的卡（审批 / 提问）
  for (const [rid, card] of Object.entries(S.cards)) {
    if (card.sessionId && card.sessionId !== S.current) continue
    el.messages.appendChild(renderCard(rid, card))
  }
  autoScroll()
}

function renderCard(rid, card) {
  if (card.kind === 'perm') return renderPermissionCard(rid, card)
  return renderQuestionCard(rid, card)
}

function renderPermissionCard(rid, card) {
  const p = card.payload
  const wrap = document.createElement('div')
  wrap.className = 'card appr'
  const t = document.createElement('div')
  t.className = 't'
  t.textContent = '🔐 需要审批：' + (p.action || '工具调用')
  wrap.appendChild(t)
  const sub = [p.resource, p.reason].filter(Boolean).join('\n')
  if (sub) {
    const s = document.createElement('div')
    s.className = 'sub'
    s.textContent = sub
    wrap.appendChild(s)
  }
  const btns = document.createElement('div')
  btns.className = 'btns'
  const opts = (p.options && p.options.length) ? p.options : [
    { id: 'approve', label: '允许' }, { id: 'reject', label: '拒绝' },
  ]
  for (const o of opts) {
    const b = document.createElement('button')
    b.textContent = o.label || o.id
    if (/reject|deny|no/i.test(o.id)) b.className = 'no'
    b.onclick = () => {
      sendSealed({ t: 'cmd.resolve_permission', cmdId: nextCmdId(), sessionId: S.current, requestId: rid, decision: o.id })
      delete S.cards[rid]
      renderMessages()
      log('审批决定：' + o.id)
    }
    btns.appendChild(b)
  }
  wrap.appendChild(btns)
  return wrap
}

function renderQuestionCard(rid, card) {
  const p = card.payload
  const wrap = document.createElement('div')
  wrap.className = 'card appr'
  const t = document.createElement('div')
  t.className = 't'
  t.textContent = '❓ 需要回答'
  wrap.appendChild(t)

  if (!S.qSel[rid]) S.qSel[rid] = {}
  const sel = S.qSel[rid]

  for (const q of (p.questions || [])) {
    const box = document.createElement('div')
    box.className = 'qq'
    const qt = document.createElement('div')
    qt.className = 'qt'
    qt.textContent = q.question
    box.appendChild(qt)
    if (!sel[q.id]) sel[q.id] = []
    for (const o of (q.options || [])) {
      const b = document.createElement('button')
      b.className = 'qopt' + (sel[q.id].includes(o.id) ? ' on' : '')
      b.textContent = o.label || o.id
      b.onclick = () => {
        if (q.multi) {
          const i = sel[q.id].indexOf(o.id)
          if (i >= 0) sel[q.id].splice(i, 1)
          else sel[q.id].push(o.id)
        } else {
          sel[q.id] = [o.id]
        }
        renderMessages()
      }
      box.appendChild(b)
    }
    wrap.appendChild(box)
  }

  const btns = document.createElement('div')
  btns.className = 'btns'
  const ok = document.createElement('button')
  ok.textContent = '提交'
  ok.onclick = () => {
    const answers = (p.questions || []).map(q => ({
      questionId: q.id,
      selected: sel[q.id] || [],
    }))
    sendSealed({ t: 'cmd.answer', cmdId: nextCmdId(), sessionId: S.current, requestId: rid, answers })
    delete S.cards[rid]
    delete S.qSel[rid]
    renderMessages()
    log('已回答提问')
  }
  btns.appendChild(ok)
  wrap.appendChild(btns)
  return wrap
}

/* ================= 命令 ================= */
function nextCmdId() {
  S.cmdSeq += 1
  return 'cmd_' + Date.now().toString(36) + '_' + S.cmdSeq
}

function sendRaw(obj) {
  if (!S.ws || S.ws.readyState !== 1) { log('连接不在了，发不出去'); return }
  S.ws.send(JSON.stringify(obj))
}

function sendSealed(payload) {
  if (!S.kC2H) { log('还没配对'); return }
  const nonce = counterNonce(S.noncePre, S.outSeq)
  const seq = S.outSeq
  S.outSeq += 1
  const rec = seal(S.kC2H, payload, nonce)
  sendRaw({ t: 'enc', sessionId: S.convId, seq, ciphertext: rec.ciphertext })
}

function cmdListSessions() {
  sendSealed({ t: 'cmd.list_sessions', cmdId: nextCmdId() })
}

function openSession(id, title) {
  S.current = id
  S.currentTitle = title || '对话'
  S.msgs = []
  S.historyLoaded = false
  S.cards = {}
  S.qSel = {}
  showView('chat')
  renderMessages()
  renderSessions()
  sendSealed({ t: 'cmd.session_history', cmdId: nextCmdId(), sessionId: id, limit: 50 })
  sendSealed({ t: 'cmd.get_pending', cmdId: nextCmdId(), sessionId: id })
}

function goBack() {
  S.current = null
  S.currentTitle = ''
  S.msgs = []
  S.cards = {}
  showView('list')
  renderSessions()
}

function cmdSendPrompt() {
  const text = (el.msgInput?.value || '').trim()
  if (!text || !S.current) return
  el.msgInput.value = ''
  S.msgs.push({ id: 'me_' + Date.now(), role: 'user', text, pending: true })
  renderMessages()
  sendSealed({ t: 'cmd.send_prompt', cmdId: nextCmdId(), sessionId: S.current, text })
}

function cmdInterrupt() {
  if (!S.current) return
  sendSealed({ t: 'cmd.interrupt', cmdId: nextCmdId(), sessionId: S.current })
  log('已请求中断')
}

/* ================= 事件归约（实时 + 历史共用） ================= */
function applyEvent(p) {
  if (!p || typeof p !== 'object') return
  const t = p.t

  // —— 全局事件（按契约 F11 不带 sessionId） ——
  if (t === 'ev.session_changed') {
    S.sessions = Array.isArray(p.sessions) ? p.sessions : []
    renderSessions()
    return
  }
  if (t === 'ev.keep_awake_state') return
  if (t === 'ev.host_info') {
    log('[host] ' + (p.host?.platform || '') + ' ' + (p.host?.pluginVersion || ''))
    return
  }
  if (t === 'ev.result') {
    if (p.ok === false) log('[result] FAIL ' + (p.message || ''))
    return
  }

  const sid = p.sessionId

  // 运行态用 sessionId 维护徽标
  if (t === 'ev.run_state') {
    if (sid) {
      S.running[sid] = p.state === 'running'
      renderSessions()
      if (S.current === sid) setStatus(p.state === 'running' ? '运行中…' : '空闲', p.state === 'running' ? '#3ecf8e' : '#8a8aa0')
    } else if (S.current === null) {
      setStatus(p.state === 'running' ? '运行中…' : '空闲', p.state === 'running' ? '#3ecf8e' : '#8a8aa0')
    }
    return
  }

  // —— 会话级事件：串台防护（别的会话的事件一律不进当前视图） ——
  if (sid && sid !== S.current) return
  // 不在任何会话里时，只收列表/挂起卡，别往空列表里塞消息
  if (S.current === null && (t === 'ev.message_delta' || t === 'ev.tool_event')) return

  switch (t) {
    case 'ev.message_delta': {
      const mid = p.messageId || ('m_' + Date.now())
      // 本机乐观插入的用户消息：host 回显同一句话时合并，避免重复
      if (p.role === 'user') {
        const idx = S.msgs.findIndex(m => m.pending && m.text === p.delta)
        if (idx >= 0) S.msgs.splice(idx, 1)
      }
      let m = S.msgs.find(x => x.id === mid && x.kind !== 'tool')
      if (!m) { m = { id: mid, kind: 'msg', role: p.role || 'assistant', text: '' }; S.msgs.push(m) }
      if (typeof p.delta === 'string') m.text += p.delta
      if (p.role) m.role = p.role
      if (p.done) m.done = true
      scheduleRender()
      break
    }
    case 'ev.tool_event': {
      const cid = p.callId || ('t_' + Date.now())
      let m = S.msgs.find(x => x.id === cid && x.kind === 'tool')
      if (!m) { m = { id: cid, kind: 'tool', text: '' }; S.msgs.push(m) }
      const head = '🔧 ' + (p.tool || p.title || '工具')
      const phase = p.phase === 'completed' ? '✓' : p.phase === 'failed' ? '✗' : '…'
      m.text = head + ' ' + phase + (p.title && p.title !== p.tool ? ' ' + p.title : '')
      if (p.resultPreview && p.phase !== 'started') m.text += '\n' + String(p.resultPreview).slice(0, 300)
      scheduleRender()
      break
    }
    case 'ev.permission_request': {
      if (!p.requestId) break
      S.cards[p.requestId] = { sessionId: sid || S.current, kind: 'perm', payload: p }
      renderMessages()
      log('收到审批请求：' + (p.action || ''))
      break
    }
    case 'ev.question_request': {
      if (!p.requestId) break
      S.cards[p.requestId] = { sessionId: sid || S.current, kind: 'q', payload: p }
      renderMessages()
      log('收到提问')
      break
    }
    case 'ev.permission_resolved':
    case 'ev.question_resolved': {
      if (p.requestId && S.cards[p.requestId]) {
        delete S.cards[p.requestId]
        delete S.qSel[p.requestId]
        renderMessages()
      }
      break
    }
    case 'ev.session_history': {
      if (!S.historyLoaded) { S.msgs = []; S.historyLoaded = true }
      const items = Array.isArray(p.items) ? p.items : []
      for (const it of items) applyEvent(it)
      renderMessages()
      break
    }
    case 'ev.todo': {
      // 待办暂不单独渲染，避免和消息抢版面
      break
    }
    case 'ev.retry':
      log('[重试] ' + p.attempt + '/' + p.max + (p.reason ? ' ' + p.reason : ''))
      break
    case 'ev.compaction':
      if (S.current === sid || !sid) setStatus('压缩上下文 ' + p.state, '#e0a83a')
      break
    default:
      log('[ev]', t, JSON.stringify(p).slice(0, 200))
  }
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
    setStatus(S.paired ? '连接断开' : '连接关闭', '#ff5c7a')
    log('连接关闭')
  }

  ws.onerror = () => { setStatus('连接出错', '#ff5c7a'); log('WebSocket 错误') }
}

function handleFrame(f) {
  const t = f.t
  if (t !== 'enc' && t !== 'enc-batch') log('[frame]', t, JSON.stringify(f).slice(0, 220))

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
      const hostPubS = f.hostPub
      const nonceS = f.nonce
      const wrappedS = f.wrappedPsk
      if (!hostPubS || !nonceS || !wrappedS) { log('pair-grant 字段缺失'); break }
      try {
        const shared = nacl.box.before(b64d(hostPubS), S.keypair.secretKey)
        const wrapKey = sha512Bytes(concatBytes(shared, te.encode(WRAP_LABEL))).subarray(0, 32)
        const s = sha512Bytes(concatBytes(shared, te.encode(SAS_LABEL))).subarray(0, 4)
        const v = ((s[0] << 24) | (s[1] << 16) | (s[2] << 8) | s[3]) >>> 0
        log('[pair-grant] SAS=' + String(v % 1000000).padStart(6, '0'))

        const psk = nacl.secretbox.open(b64d(wrappedS), b64d(nonceS), wrapKey)
        if (!psk) { setStatus('密钥解开失败', '#ff5c7a'); log('psk 解密失败'); break }
        if (psk.length !== 16) { setStatus('PSK 长度不对', '#ff5c7a'); break }
        S.pskBytes = psk
        if (f.sessionId) S.convId = f.sessionId
        tryFinishPairing()
      } catch (e) {
        log('pair-grant 异常', String(e))
      }
      break
    }

    case 'paired': {
      S.convId = f.sessionId || S.convId
      tryFinishPairing()
      break
    }

    case 'enc': {
      if (!S.kH2C) return
      const payload = openRecord(S.kH2C, f)
      if (payload) applyEvent(payload)
      break
    }

    case 'enc-batch': {
      if (!S.kH2C) return
      for (const it of (Array.isArray(f.items) ? f.items : [])) {
        const payload = openRecord(S.kH2C, it)
        if (payload) applyEvent(payload)
      }
      break
    }

    case 'error':
      setStatus('中继错误: ' + (f.code || ''), '#ff5c7a')
      log('error', f.code, f.message || '')
      break

    case 'peer-left':
      setStatus('主机已离开', '#ff5c7a')
      log('peer-left：主机离开')
      break

    case 'resume-gap':
      log('resume-gap：' + (f.reason || ''))
      break

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
  log('配对完成，拉会话列表')
  S.sessions = []
  S.current = null
  S.msgs = []
  S.cards = {}
  S.running = {}
  showView('list')
  renderSessions()
  cmdListSessions()
  sendSealed({ t: 'cmd.get_pending', cmdId: nextCmdId() })
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
  el.backBtn?.addEventListener('click', goBack)
  el.sendBtn?.addEventListener('click', cmdSendPrompt)
  el.stopBtn?.addEventListener('click', cmdInterrupt)
  el.msgInput?.addEventListener('keydown', (e) => { if (e.key === 'Enter') cmdSendPrompt() })
  el.clearLog?.addEventListener('click', () => { logLines.length = 0; if (el.log) el.log.textContent = '' })

  setStatus('未连接')
  showView('pair')
  log('客户端已加载，中继: ' + S.relay)
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot)
} else {
  boot()
}
