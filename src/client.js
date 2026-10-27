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
  mode: 'pair',          // 'pair' = 输码配对；'resume' = 用存下来的会话重连
  gotData: false,        // 重连后是否收到过数据（看门狗用）
  hostAway: false,       // 收到过「主机暂时离线」的提示
  reconnectTimer: 0,
  reconnectTries: 0,
  pingTimer: 0,
  logOpen: false,      // 日志栏是否展开（默认收起；用户可随时切换并记住）
  lastSent: null,      // 最近一次发出的 prompt：{ text, at }，用于识别 host 的重复回显
  replaying: false,    // 正在回放历史（历史里的同文本消息不能按"重复"去重）
  catalog: null,       // 电脑端返回的模型清单 { default, groups:[{id,name,models:[{id,name,efforts?,defaultEffort?}]}] }
  modelOf: readModelMap(),   // 每个会话记一份「上次选的模型 + 努力程度」
  hostModel: {},       // 电脑端 ev.model 广播来的真实模型名（用来显示；没选过时当兜底）
}

/* 模型选择按会话记在本地：重启 App 也能显示上次选的 */
function readModelMap() {
  try {
    const raw = localStorage.getItem('drc.models')
    const obj = raw ? JSON.parse(raw) : null
    return obj && typeof obj === 'object' ? obj : {}
  } catch (_) { return {} }
}
function saveModelMap() {
  try { localStorage.setItem('drc.models', JSON.stringify(S.modelOf)) } catch (_) {}
}

/* ================= DOM ================= */
const $ = (id) => document.getElementById(id)
const el = {}
function initEls() {
  const ids = ['status', 'title', 'backBtn', 'pairView', 'listView', 'chatView', 'logCard',
    'pairCode', 'connectBtn', 'relayUrl', 'saveRelayBtn', 'sessions', 'refreshBtn', 'repairBtn', 'updateBtn',
    'messages', 'msgInput', 'sendBtn', 'stopBtn', 'composer', 'log', 'clearLog', 'logToggleBtn', 'main', 'reconnectBtn',
    'modelBtn', 'renameBtn', 'dlgWrap', 'dlgTitle', 'dlgInput', 'dlgOk', 'dlgCancel',
    'modelWrap', 'modelList', 'modelRefresh', 'modelClose']
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

// 重连成功后收到数据：把状态从「重连中…」切回「已连接」；
// 之前挂过「主机暂时离线」的，数据一到也立刻恢复。
function noteConnected() {
  const first = !S.gotData
  S.gotData = true
  if (S.mode !== 'resume') return
  if (first) {
    setStatus('已连接', '#3ecf8e')
    log('重连成功')
  } else if (S.hostAway) {
    S.hostAway = false
    setStatus('已连接', '#3ecf8e')
    log('主机恢复在线')
  }
}

/* ================= 会话持久化 / 重连 ================= */
function loadSession() {
  try {
    const psk = localStorage.getItem('drc.psk')
    const conv = localStorage.getItem('drc.conv')
    if (!psk || !conv) return null
    return { psk: b64d(psk), conv }
  } catch (_) { return null }
}

function saveSession(pskBytes, conv) {
  localStorage.setItem('drc.psk', b64e(pskBytes))
  localStorage.setItem('drc.conv', conv)
}

function clearSession() {
  localStorage.removeItem('drc.psk')
  localStorage.removeItem('drc.conv')
  localStorage.removeItem('drc.seq')
}

function stopPing() {
  if (S.pingTimer) { clearInterval(S.pingTimer); S.pingTimer = 0 }
}

function startPing() {
  stopPing()
  // 25 秒一次心跳：既防中间设备掐空闲连接，也检测链路是否还活着
  S.pingTimer = setInterval(() => {
    if (S.ws && S.ws.readyState === 1) sendRaw({ t: 'ping', ts: Date.now() })
  }, 25000)
}

function stopReconnect() {
  if (S.reconnectTimer) { clearTimeout(S.reconnectTimer); S.reconnectTimer = 0 }
}

function scheduleReconnect() {
  if (S.reconnectTimer) return
  if (!loadSession()) {
    S.paired = false
    setStatus('已断开，需要重新配对', '#ff5c7a')
    showView('pair')
    return
  }
  S.reconnectTries += 1
  const delay = Math.min(30000, 1500 * Math.pow(1.6, S.reconnectTries - 1))
  setStatus('断开，' + Math.round(delay / 1000) + ' 秒后重连…', '#e0a83a')
  if (el.reconnectBtn) el.reconnectBtn.hidden = false
  S.reconnectTimer = setTimeout(() => {
    S.reconnectTimer = 0
    connect()
  }, delay)
}

/* ================= 视图切换 ================= */
function showView(name) {
  S.view = name
  el.pairView.hidden = name !== 'pair'
  el.listView.hidden = name !== 'list'
  el.chatView.hidden = name !== 'chat'
  el.logCard.hidden = !S.logOpen   // 日志栏展开/收起由用户决定，换页不重置
  el.composer.hidden = name !== 'chat'
  el.backBtn.hidden = name !== 'chat'
  if (el.title) el.title.textContent = name === 'chat' ? (S.currentTitle || '对话') : '大肥鱼远控'
  if (el.renameBtn) el.renameBtn.hidden = name !== 'chat'
  if (el.modelBtn) {
    el.modelBtn.hidden = name !== 'chat'
    if (name === 'chat') el.modelBtn.textContent = modelBadgeText()
  }
  if (el.dlgWrap) el.dlgWrap.hidden = true
  if (el.modelWrap) el.modelWrap.hidden = true
  if (name === 'chat' && el.main) el.main.scrollTop = el.main.scrollHeight
  if (el.reconnectBtn) el.reconnectBtn.hidden = !!S.paired
  if (el.logToggleBtn) el.logToggleBtn.textContent = S.logOpen ? '收起' : '日志'
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

function workspaceLabel(ws) {
  if (!ws) return '未指定工作区'
  const parts = String(ws).split(/[\\/]+/).filter(Boolean)
  if (!parts.length) return String(ws)
  return parts.length > 2 ? parts.slice(-2).join('/') : parts.join('/')
}

function renderSessions() {
  if (!el.sessions) return
  el.sessions.innerHTML = ''

  // 过滤：委派子会话 + 没有标题的（这两类点进去必然是空的）
  const list = S.sessions
    .map(raw => raw.session ?? raw)
    .filter(s => s.origin !== 'subagent')
    .filter(s => typeof s.title === 'string' && s.title.trim().length > 0)

  if (!list.length) {
    const d = document.createElement('div')
    d.className = 'muted'
    d.textContent = '还没有会话（点刷新试试）'
    el.sessions.appendChild(d)
    return
  }

  // 按工作区分组
  const groups = new Map()
  for (const s of list) {
    const key = s.workspace || ''
    if (!groups.has(key)) groups.set(key, [])
    groups.get(key).push(s)
  }

  for (const [ws, items] of groups) {
    const h = document.createElement('div')
    h.className = 'ws'
    h.textContent = workspaceLabel(ws) + '（' + items.length + '）'
    const add = document.createElement('button')
    add.className = 'wsAdd'
    add.textContent = '＋ 新会话'
    add.title = '在这个工作区里新建会话'
    add.onclick = (e) => { e.stopPropagation(); cmdNewSession(ws) }
    h.appendChild(add)
    el.sessions.appendChild(h)

    for (const s of items) {
      const id = s.id || s.sessionId || s.convId || ''
      const title = s.title
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
  // 空状态：至少告诉用户"这里没内容"，而不是一片空白
  if (!S.msgs.length && Object.keys(S.cards).length === 0) {
    const d = document.createElement('div')
    d.className = 'muted'
    d.textContent = S.historyLoaded ? '（这个会话没有消息）' : '加载中…'
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
  // 序号必须跨重连继续递增：同一个 PSK 下重复 nonce 会毁掉加密
  try { localStorage.setItem('drc.seq', String(S.outSeq)) } catch (_) {}
  const rec = seal(S.kC2H, payload, nonce)
  sendRaw({ t: 'enc', sessionId: S.convId, seq, ciphertext: rec.ciphertext })
}

function cmdListSessions() {
  sendSealed({ t: 'cmd.list_sessions', cmdId: nextCmdId() })
}

/* ================= 新建会话（指定工作区） ================= */
function cmdNewSession(workspace) {
  if (!S.kC2H) { log('还没配对'); return }
  setStatus('新建会话…')
  log('[新建会话] ' + (workspace || '默认工作区'))
  sendSealed({ t: 'cmd.new_session', cmdId: nextCmdId(), ...(workspace ? { workspace } : {}) })
}

/* ================= 改会话名称 ================= */
function openRenameDialog() {
  if (!S.current || !el.dlgWrap) return
  el.dlgTitle.textContent = '会话名称'
  el.dlgInput.value = S.currentTitle || ''
  el.dlgWrap.hidden = false
  setTimeout(() => { try { el.dlgInput.focus(); el.dlgInput.select() } catch (_) {} }, 30)
}
function closeRenameDialog() {
  if (el.dlgWrap) el.dlgWrap.hidden = true
}
function doRename() {
  const title = (el.dlgInput?.value || '').trim()
  if (!title || !S.current) { closeRenameDialog(); return }
  closeRenameDialog()
  setStatus('改名…')
  log('[改名] ' + title)
  sendSealed({ t: 'cmd.rename_session', cmdId: nextCmdId(), sessionId: S.current, title })
}

/* ================= 模型 / 努力程度 ================= */
// 当前会话显示的模型：手机选过的优先，没选过就用电脑端广播的那个
function effectiveModel() {
  if (!S.current) return null
  const picked = S.modelOf[S.current]
  if (picked && picked.model) return picked
  const host = S.hostModel[S.current]
  if (host && host.model) return host
  if (S.catalog?.default?.model) return S.catalog.default
  return null
}
function modelBadgeText() {
  const sel = effectiveModel()
  const name = sel?.model || ''
  if (!name) return '模型'
  return String(name).replace(/^.*\//, '')
}
function refreshModelBadge() {
  if (el.modelBtn && S.view === 'chat') el.modelBtn.textContent = modelBadgeText()
}
function findModel(provider, model) {
  const groups = S.catalog?.groups || []
  const g = groups.find(x => x.id === provider)
  return g?.models?.find(m => m.id === model)
}
function openModelSheet() {
  if (!S.current || !el.modelWrap) return
  el.modelWrap.hidden = false
  if (!S.catalog) {
    setStatus('取模型清单…')
    log('[模型] 向电脑端要清单')
    sendSealed({ t: 'cmd.get_models', cmdId: nextCmdId() })
  } else {
    renderModelSheet()
  }
}
function closeModelSheet() {
  if (el.modelWrap) el.modelWrap.hidden = true
}
function pickModel(provider, model, effort) {
  if (!S.current) return
  log('[模型] ' + provider + '/' + model + (effort ? ' · ' + effort : ''))
  setStatus('切换模型…')
  sendSealed({
    t: 'cmd.set_model', cmdId: nextCmdId(), sessionId: S.current,
    provider, model, ...(effort ? { reasoningEffort: effort } : {})
  })
}
function renderModelSheet() {
  if (!el.modelList) return
  el.modelList.innerHTML = ''
  const groups = S.catalog?.groups || []
  if (!groups.length) {
    const d = document.createElement('div')
    d.className = 'muted'
    d.textContent = S.catalog ? '这台电脑上没有可用模型' : '正在取模型清单…'
    el.modelList.appendChild(d)
    return
  }
  const sel = effectiveModel()
  for (const g of groups) {
    const gh = document.createElement('div')
    gh.className = 'mgroup'
    gh.textContent = g.name || g.id
    el.modelList.appendChild(gh)
    for (const m of g.models || []) {
      const on = sel && sel.model === m.id && (!sel.provider || sel.provider === g.id)
      const b = document.createElement('button')
      b.className = 'mitem' + (on ? ' on' : '')
      const n = document.createElement('span'); n.className = 'n'; n.textContent = m.name || m.id
      b.appendChild(n)
      if (m.efforts?.length) {
        const k = document.createElement('span'); k.className = 'k'; k.textContent = '可调档'
        b.appendChild(k)
      }
      b.onclick = () => pickModel(g.id, m.id, m.defaultEffort || '')
      el.modelList.appendChild(b)

      // 当前模型才展开努力程度档位（省屏幕）
      if (on && m.efforts?.length) {
        const row = document.createElement('div')
        row.className = 'eff'
        const cur = sel.reasoningEffort || m.defaultEffort || ''
        for (const effort of m.efforts) {
          const eb = document.createElement('button')
          eb.className = effort.id === cur ? 'on' : ''
          eb.textContent = effort.name || effort.id
          eb.onclick = () => pickModel(g.id, m.id, effort.id)
          row.appendChild(eb)
        }
        el.modelList.appendChild(row)
      }
    }
  }
}

function openSession(id, title) {
  S.current = id
  S.currentTitle = title || '对话'
  S.msgs = []
  S.historyLoaded = false
  S.cards = {}
  S.qSel = {}
  S.lastSent = null
  showView('chat')
  renderMessages()
  renderSessions()
  refreshModelBadge()
  sendSealed({ t: 'cmd.session_history', cmdId: nextCmdId(), sessionId: id, limit: 50 })
  sendSealed({ t: 'cmd.get_pending', cmdId: nextCmdId(), sessionId: id })
}

function goBack() {
  S.current = null
  S.currentTitle = ''
  S.msgs = []
  S.cards = {}
  S.lastSent = null
  showView('list')
  renderSessions()
}

function cmdSendPrompt() {
  const text = (el.msgInput?.value || '').trim()
  if (!text || !S.current) return
  el.msgInput.value = ''
  S.lastSent = { text, at: Date.now() }
  S.msgs.push({ id: 'me_' + Date.now(), kind: 'msg', role: 'user', text, pending: true, at: Date.now() })
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
    const d = p.data && typeof p.data === 'object' ? p.data : null
    if (p.ok === false) {
      log('[result] FAIL ' + (p.message || ''))
      if (p.message) setStatus(String(p.message).slice(0, 40), '#e0a83a')
    }
    if (d) {
      // 模型清单（cmd.get_models 的回执）
      if (d.kind === 'catalog' && d.catalog) {
        S.catalog = d.catalog
        if (Array.isArray(d.failures) && d.failures.length) log('[模型] 部分 provider 取不到：' + d.failures.map(x => x.id).join(','))
        renderModelSheet()
        refreshModelBadge()
      }
      // 切模型成功
      if (d.kind === 'model' && d.selected) {
        if (d.sessionId) {
          S.modelOf[d.sessionId] = { ...d.selected }
          saveModelMap()
        }
        refreshModelBadge()
        renderModelSheet()
        setStatus('模型已切换', '#3ecf8e')
        closeModelSheet()
      }
      // 改名成功
      if (d.kind === 'title' && d.title) {
        if (d.sessionId && d.sessionId === S.current) {
          S.currentTitle = d.title
          if (el.title) el.title.textContent = d.title
        }
        setStatus('已改名', '#3ecf8e')
      }
      // 新建会话成功 → 直接进去
      if (d.sessionId && !d.kind) {
        log('[新建会话] 已创建 ' + d.sessionId)
        openSession(d.sessionId, '新会话')
      }
    }
    return
  }

  const sid = p.sessionId

  // 电脑端广播的当前模型：canSwitch 一直是 false（插件那一代不支持），但 model 名是真的
  if (t === 'ev.model') {
    if (sid && p.model) {
      S.hostModel[sid] = { provider: p.provider || '', model: p.model }
      if (S.current === sid) {
        refreshModelBadge()
        if (el.modelWrap && !el.modelWrap.hidden) renderModelSheet()
      }
    }
    return
  }

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
      const text = typeof p.delta === 'string' ? p.delta : ''

      // —— 用户消息：host 对同一条消息可能发两帧（排队消息先走 agent/inbox/spliced，
      //    进正史后 user/message 再发一次；两帧的 messageId 可能相同也可能不同，
      //    时间间隔可达数分钟）——同一条消息只允许一个气泡、文本绝不叠加 ——
      if (p.role === 'user') {
        // a) 同 messageId 的气泡
        let m = S.msgs.find(x => x.kind !== 'tool' && x.id === mid)
        // b) 本机刚发出的那条：优先认领乐观气泡（它就是"这条消息"）
        if (!m && !S.replaying && text && S.lastSent && S.lastSent.text === text) {
          const pend = S.msgs.find(x => x.pending && x.text === text)
          if (pend) {
            pend.id = mid
            pend.pending = false
            pend.at = Date.now()
            m = pend
          }
        }
        // c) 同一句话最近已经渲染过（重复回显的第二帧 / 迟到的 inbox 帧）
        if (!m && !S.replaying && text && S.lastSent && S.lastSent.text === text) {
          const dup = S.msgs.find(x => x.kind === 'msg' && x.role === 'user' && !x.pending && x.text === text)
          if (dup) {
            dup.id = mid
            m = dup
            log('[去重] 同文本用户消息只保留一个气泡')
          }
        }
        if (!m) {
          m = { id: mid, kind: 'msg', role: 'user', text, at: Date.now() }
          S.msgs.push(m)
        } else if (text && m.text !== text && text.startsWith(m.text)) {
          m.text = text
        }
        if (p.done) m.done = true
        scheduleRender()
        break
      }

      // —— 助理 / 其它角色：原有流式拼接 ——
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
      S.replaying = true
      for (const it of items) applyEvent(it)
      S.replaying = false
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
function connect(forcePair) {
  const stored = loadSession()
  let mode

  if (forcePair === true) {
    const code = (el.pairCode?.value || '').trim()
    if (!/^\d{6}$/.test(code)) { setStatus('配对码要 6 位数字', '#ff5c7a'); return }
    clearSession()
    S.pendingCode = code
    S.pskBytes = null
    S.convId = ''
    mode = 'pair'
  } else if (stored) {
    S.pendingCode = ''
    S.pskBytes = stored.psk
    S.convId = stored.conv
    mode = 'resume'
  } else {
    setStatus('请先输入配对码', '#ff5c7a')
    showView('pair')
    return
  }

  S.mode = mode
  stopReconnect()
  S.paired = false
  S.gotData = false
  S.kC2H = null
  S.kH2C = null
  S.keypair = nacl.box.keyPair()
  // 配对新一代 PSK 时序号从 1 开始；重连必须接着上次的序号，否则 nonce 重用
  S.outSeq = mode === 'pair' ? 1 : (parseInt(localStorage.getItem('drc.seq') || '1', 10) || 1)

  setStatus(mode === 'resume' ? '重连中…' : '连接中…', '#5b8cff')
  log((mode === 'resume' ? '重连 ' : '连接 ') + S.relay)

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
    stopPing()
    if (S.ws !== ws) return   // 主动换连接，忽略旧 socket 的关闭
    log('连接关闭')
    if (S.paired || S.mode === 'resume') scheduleReconnect()
    else setStatus('连接关闭', '#ff5c7a')
  }

  ws.onerror = () => { log('WebSocket 错误') }
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
      if (S.mode === 'resume' && S.pskBytes && S.convId) {
        S.kC2H = deriveKey(S.pskBytes, 'c2h', S.convId)
        S.kH2C = deriveKey(S.pskBytes, 'h2c', S.convId)
        S.noncePre = noncePrefix(S.pskBytes, S.convId, S.clientId || 'anon')
        S.paired = true
        S.gotData = false
        startPing()
        setStatus('重连中…', '#5b8cff')
        S.current = null
        S.msgs = []
        S.cards = {}
        showView('list')
        renderSessions()
        cmdListSessions()
        // 5 秒看门狗：重连后没有任何数据，提示一下（不销毁会话，避免误判）
        setTimeout(() => {
          if (!S.gotData && S.mode === 'resume') {
            log('重连后 5 秒仍无数据')
            setStatus('重连无响应，可点重连重试', '#e0a83a')
          }
        }, 5000)
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
      if (payload) { noteConnected(); applyEvent(payload) }
      break
    }

    case 'enc-batch': {
      if (!S.kH2C) return
      for (const it of (Array.isArray(f.items) ? f.items : [])) {
        const payload = openRecord(S.kH2C, it)
        if (payload) { noteConnected(); applyEvent(payload) }
      }
      break
    }

    case 'error':
      log('error', f.code, f.message || '')
      // 主机掉线的报错：当临时提示，数据回来就自动恢复，不吓人也不断连接
      if (/host|peer|offline|gone/i.test(f.code || '')) {
        S.hostAway = true
        setStatus('主机暂时离线，等待恢复…', '#e0a83a')
      } else if (!/session|unpaired|expired/i.test(f.code || '')) {
        setStatus('中继错误: ' + (f.code || ''), '#ff5c7a')
      }
      // 会话已被作废：存的那份 PSK 没用了，回去重新配对
      if (/session|unpaired|expired/i.test(f.code || '')) {
        clearSession()
        S.mode = 'pair'
        S.paired = false
        showView('pair')
      }
      break

    case 'peer-left':
      // 不致命：只是 relay 报告主机那边断过线；数据回来就自动变「已连接」
      S.hostAway = true
      setStatus('主机暂时离线，等待恢复…', '#e0a83a')
      log('peer-left：主机暂时离线')
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
  S.mode = 'resume'
  S.reconnectTries = 0
  S.kC2H = deriveKey(S.pskBytes, 'c2h', S.convId)
  S.kH2C = deriveKey(S.pskBytes, 'h2c', S.convId)
  S.noncePre = noncePrefix(S.pskBytes, S.convId, S.clientId || 'anon')
  S.outSeq = 1
  saveSession(S.pskBytes, S.convId)
  startPing()

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
// 原生更新流程的每一步会推到这里：写进日志栏，并让状态栏实时可见
window.__onUpdateLog = (s) => {
  log('[更新] ' + s)
  setStatus('更新: ' + s, '#e0a83a')
}

function boot() {
  initEls()

  // 日志栏偏好：记住上次是收起还是展开（默认收起）
  S.logOpen = localStorage.getItem('drc.logOpen') === '1'
  el.logCard.hidden = !S.logOpen
  if (el.logToggleBtn) el.logToggleBtn.textContent = S.logOpen ? '收起' : '日志'

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

  el.connectBtn?.addEventListener('click', () => connect(true))
  el.pairCode?.addEventListener('keydown', (e) => { if (e.key === 'Enter') connect(true) })
  el.refreshBtn?.addEventListener('click', () => { if (S.paired) cmdListSessions() })
  el.updateBtn?.addEventListener('click', () => {
    try { window.dshApp.checkUpdate() } catch (_) { log('「更新」只在 App 内可用') }
  })
  el.backBtn?.addEventListener('click', goBack)
  el.sendBtn?.addEventListener('click', cmdSendPrompt)
  el.stopBtn?.addEventListener('click', cmdInterrupt)
  el.msgInput?.addEventListener('keydown', (e) => { if (e.key === 'Enter') cmdSendPrompt() })

  // 改名
  el.renameBtn?.addEventListener('click', openRenameDialog)
  el.dlgOk?.addEventListener('click', doRename)
  el.dlgCancel?.addEventListener('click', closeRenameDialog)
  el.dlgInput?.addEventListener('keydown', (e) => { if (e.key === 'Enter') doRename() })
  el.dlgWrap?.addEventListener('click', (e) => { if (e.target === el.dlgWrap) closeRenameDialog() })

  // 模型 / 努力程度
  el.modelBtn?.addEventListener('click', openModelSheet)
  el.modelClose?.addEventListener('click', closeModelSheet)
  el.modelWrap?.addEventListener('click', (e) => { if (e.target === el.modelWrap) closeModelSheet() })
  el.modelRefresh?.addEventListener('click', () => {
    S.catalog = null
    sendSealed({ t: 'cmd.get_models', cmdId: nextCmdId() })
    renderModelSheet()
  })
  el.clearLog?.addEventListener('click', () => { logLines.length = 0; if (el.log) el.log.textContent = '' })

  // 日志栏：点「日志」展开，再点「收起」缩回；选择会被记住
  el.logToggleBtn?.addEventListener('click', () => {
    S.logOpen = !S.logOpen
    localStorage.setItem('drc.logOpen', S.logOpen ? '1' : '0')
    el.logCard.hidden = !S.logOpen
    el.logToggleBtn.textContent = S.logOpen ? '收起' : '日志'
  })

  el.reconnectBtn?.addEventListener('click', () => {
    S.reconnectTries = 0
    stopReconnect()
    connect()
  })

  // 重新配对：清掉旧会话，回到配对页
  el.repairBtn?.addEventListener('click', () => {
    clearSession()
    stopReconnect()
    stopPing()
    try { S.ws?.close() } catch (_) {}
    S.ws = null
    S.mode = 'pair'
    S.paired = false
    showView('pair')
    setStatus('请输入新的配对码')
  })

  // 回到前台立刻重连，不等退避；切后台时靠前台服务+心跳尽量撑住
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) return
    if (S.ws && S.ws.readyState === 1) return
    if (loadSession()) {
      S.reconnectTries = 0
      stopReconnect()
      connect()
    }
  })

  setStatus('未连接')
  log('客户端已加载，中继: ' + S.relay)

  if (loadSession()) {
    log('发现已保存的配对，自动重连')
    connect()
  } else {
    showView('pair')
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot)
} else {
  boot()
}
