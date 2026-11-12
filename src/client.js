/* 大肥鱼远控 —— 客户端
 *
 * 协议：dsh-rc/1（DSH Remote Control wire protocol），端到端加密（XSalsa20-Poly1305）。
 * 加密/哈希用官方同款实现（tweetnacl / js-sha512），KDF 严格按 SPEC 契约 B4-B6；
 * 配对用 X25519 + SAS（crypto/sas.ts 的 "dsh-rc/psk-wrap" 包裹）。
 */
import nacl from 'tweetnacl'
import sha512Module from 'js-sha512'
import { findImagePaths } from './imgpath.js'

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
  fresh: {},           // 刚在手机上新建、还没标题的会话（列表里别藏起来）
  cmdNames: {},        // cmdId → 'rename' | 'models' | 'set_model'（失败时给提示用）
  ackWaiters: {},      // cmdId → 回执回调（req/ev.result 一对一：看图、刷新列表）
  imgBusy: {},         // 图片路径 → 正在取（防连点）
  imgCache: {},        // 图片路径 → { url, name, bytes }（同一路径不重复取）
  modelErr: '',        // 取模型清单失败的原因
  newBusy: false,      // 正在新建会话（防连点）
  newBusyTimer: null,
  cfTimer: 0,          // 重新配对确认框的倒计时
  runStart: {},              // 会话 id → 本轮开始时间（聊天页顶部的「深度求索中…」计时）
  runDone: {},               // 会话 id → { at, ms }：刚跑完的那一轮（列表/聊天页短暂显示「已完成」）
  step: {},                  // 会话 id → 本轮进展快照 { todos, total, done, doing, retry, compact, wrote }
  lastAct: {},               // 会话 id → 最近一次有业务事件的时间（「最后活动」用）
  liveCmd: '',               // 聊天页 5 秒一次的运行态轮询 cmdId
  fishTalkUntil: 0,
  fishPokeUntil: 0,
  fishAnswerUntil: 0,
  fishDoneUntil: 0,
  fishIdleSince: 0,          // 进入 idle 的时刻（等太久就躺下睡觉）
  nextBeforeSeq: undefined,  // 历史翻页游标（还有更早的一页时才有）
  earlierBusy: false,        // 「加载更早」正在请求（防连点）
  refreshBusy: false,        // 「刷新」正在等回执（防连点）
  listStamp: 0,              // 上次成功拿到会话列表的时刻
  lastInbound: 0,            // 最近一次从中继收到任何帧（链路看门狗用）
  deadAt: 0,                 // 上次判定「链路已死」的时刻（防重复重连）
}
/*
 * 手机端**没有**「派活助手 / 子代理监视器」了（2026-11-12 用户裁决）：
 * 手机上不需要看派活池，直接跟包工头（主会话）说话就行。原来这里有一套
 * `cmd.list_subagents` 的自适应轮询（在跑 3s / 全闲 30s / 面板关 60s），
 * 那是「一次都没人看的面板」换来的持续负载 —— 连同面板 DOM、徽标、
 * 归档按钮、`S.sub*` 状态字段、`ev.result` 的子代理回执分支一并摘掉了。
 * 别再往回加：需要看派活在电脑上看。
 */

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
    'gearBtn', 'menuWrap', 'menuClose', 'confirmWrap', 'cfTitle', 'cfText', 'cfOk', 'cfCancel',
    'modelWrap', 'modelList', 'modelRefresh', 'modelClose',
    'fishFab', 'fishBubble', 'fishBody', 'fishSprite', 'fishImg', 'earlierWrap', 'earlierBtn', 'runBanner', 'runText', 'runSub', 'listMeta']
  for (const k of ids) el[k] = $(k)
}

function setStatus(text, color) {
  S.statusText = text
  if (el.status) {
    el.status.textContent = text
    el.status.style.color = color || '#8a8aa0'
  }
  fishSync()
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
  clearCaches()
  localStorage.removeItem('drc.psk')
  localStorage.removeItem('drc.conv')
  localStorage.removeItem('drc.seq')
  localStorage.removeItem('drc.open')
}

// 记住当前打开的会话：WebView 被系统杀掉重载、或者 App 被清后台后重进，
// 都还能回到原来那条会话，而不是被扔回列表
function saveOpenSession(id, title) {
  try {
    if (!id) { localStorage.removeItem('drc.open'); return }
    localStorage.setItem('drc.open', JSON.stringify({ id, title: title || '' }))
  } catch (_) {}
}
function loadOpenSession() {
  try {
    const raw = localStorage.getItem('drc.open')
    if (!raw) return null
    const obj = JSON.parse(raw)
    return obj && typeof obj.id === 'string' && obj.id ? obj : null
  } catch (_) { return null }
}
function clearOpenSession() {
  try { localStorage.removeItem('drc.open') } catch (_) {}
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
  if (el.menuWrap) el.menuWrap.hidden = true
  if (el.confirmWrap) { clearTimeout(S.cfTimer); S.cfTimer = 0; el.confirmWrap.hidden = true }
  if (name === 'chat' && el.main) el.main.scrollTop = el.main.scrollHeight
  if (el.reconnectBtn) el.reconnectBtn.hidden = !!S.paired
  if (el.logToggleBtn) el.logToggleBtn.textContent = S.logOpen ? '📜 收起日志' : '📜 日志'
  fishSync()
}

/* ================= 会话列表（含状态徽标） ================= */
/*
 * 「这条会话是死是活、在干嘛」必须在列表上一眼看见（2026-11-12 用户：
 * 「现在看不到会话是死是活，在干嘛，只能盲等」）。
 * 所以每行给三样东西：**状态文字**（不是只靠颜色点）+ **最后活动时间** + 刚跑完的
 * 「已完成」闪现。状态来源只有主机已经在发的东西：`ev.session_changed` 的
 * `state`/`running`/`updatedAt`，以及加密的 `ev.run_state`。
 */
const RUN_DONE_FLASH_MS = 6000

function sessionState(s) {
  const id = s.id
  // 刚跑完：给一次短暂的「已完成」，否则状态会从「运行中」直接跳回「空闲」，
  // 用户分不清"跑完了"和"根本没跑"。
  const done = S.runDone[id]
  if (!S.running[id] && done && Date.now() < done.until) {
    return { cls: 'ok', text: '✓ 已完成' }
  }
  if (S.running[id]) return { cls: 'run', text: '● 运行中' }
  switch (s.state) {
    case 'running': return { cls: 'run', text: '● 运行中' }
    case 'awaiting-permission': return { cls: 'attn', text: '🔐 待审批' }
    case 'awaiting-answer': return { cls: 'attn', text: '❓ 待回答' }
    case 'detached': return { cls: 'off', text: '⚠ 已脱离' }
    case 'archived': return { cls: 'arch', text: '📦 已归档' }
    default: return { cls: '', text: '空闲' }
  }
}

/** 这一行"最后动过"是什么时候：本地看到的事件优先，其次主机给的 updatedAt。 */
function lastActivityText(s) {
  const id = s.id
  const local = S.lastAct[id] || 0
  const fromHost = s.updatedAt ? (Date.parse(s.updatedAt) || 0) : 0
  const at = Math.max(local, fromHost)
  return at ? fmtAgo(at) : ''
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
    // 没标题的会话一般藏起来（桌面端那些空会话太占屏）；但刚在手机上新建的、
    // 以及正开着的，要留着 —— 否则「新建完返回列表就找不到它」
    .filter(s => {
      const id = s.id || s.sessionId || s.convId || ''
      const titled = typeof s.title === 'string' && s.title.trim().length > 0
      return titled || S.fresh[id] || id === S.current
    })
    // 同一个工作区只留一个空会话：连点 ＋ 留下的那一堆别再显示（数据还在，只是不占屏）
    .filter((s, i, arr) => {
      const id = s.id || s.sessionId || s.convId || ''
      const titled = typeof s.title === 'string' && s.title.trim().length > 0
      if (titled) return true
      if (id === S.current) return true
      const firstEmpty = arr.find(x => {
        const xt = typeof x.title === 'string' && x.title.trim().length > 0
        return !xt && (x.workspace || '') === (s.workspace || '')
      })
      const firstId = firstEmpty ? (firstEmpty.id || firstEmpty.sessionId || firstEmpty.convId || '') : ''
      return firstId === id
    })

  if (!list.length) {
    const d = document.createElement('div')
    d.className = 'muted'
    d.textContent = '还没有会话（点刷新试试）'
    el.sessions.appendChild(d)
    setListMeta(S.listStamp ? '已更新 ' + fmtClock(S.listStamp) + ' · 0 条会话' : '还没拉到列表（点刷新）')
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
    add.textContent = S.newBusy ? '建中…' : '＋ 新会话'
    add.disabled = S.newBusy
    add.title = '在这个工作区里新建会话'
    add.onclick = (e) => { e.stopPropagation(); cmdNewSession(ws) }
    h.appendChild(add)
    el.sessions.appendChild(h)

    for (const s of items) {
      const id = s.id || s.sessionId || s.convId || ''
      const titled = typeof s.title === 'string' && s.title.trim().length > 0
      if (titled) delete S.fresh[id]
      const title = titled ? s.title : '新会话'
      const st = sessionState(s)
      const btn = document.createElement('button')
      btn.className = 'session' + (S.current === id ? ' active' : '')
      const t = document.createElement('span'); t.className = 't'; t.textContent = title
      const ago = lastActivityText(s)
      const when = document.createElement('span')
      when.className = 'when'
      when.textContent = ago
      const b = document.createElement('span'); b.className = 'badge ' + st.cls; b.textContent = st.text
      btn.appendChild(t)
      if (ago) btn.appendChild(when)
      btn.appendChild(b)
      btn.title = [title, ago ? '最后活动 ' + ago : '', st.text].filter(Boolean).join(' · ')
      btn.onclick = () => openSession(id, title)
      el.sessions.appendChild(btn)
    }
  }
  // 列表页的"新鲜度"：没有它，用户没法判断手上这一页是不是几小时前的
  const stamp = S.listStamp
    ? '已更新 ' + fmtClock(S.listStamp) + ' · ' + list.length + ' 条会话'
    : '还没拉到列表（点刷新）'
  setListMeta(stamp)
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
    // 助理/系统消息里出现的图片路径 → 一颗「点我看图」的按钮（用户消息不认：那是自己打的字）
    // 兜住异常：看图出 bug 顶多没有按钮，绝不能把整页聊天气泡搞崩（这是用户的日常工具）
    if (m.kind === 'msg' && m.role !== 'user' && m.text) {
      try {
        appendImageBits(d, m)
      } catch (e) {
        log('[看图] 渲染失败 ' + (e && e.message ? e.message : e))
      }
    }
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
  scheduleCacheSave()
}

// 一个气泡里的「看图」部分：路径按钮 + 已经取到的图片。
// 路径识别按正文长度缓存：流式追加时每帧都跑正则是白烧 CPU。
function appendImageBits(d, m) {
  if (m.imgKey !== m.text.length) {
    m.imgKey = m.text.length
    m.imgPaths = findImagePaths(m.text)
  }
  const paths = m.imgPaths || []
  if (paths.length) {
    const wrap = document.createElement('div')
    wrap.className = 'imgchips'
    for (const p of paths) {
      if (S.imgCache[p]) continue          // 已经取到了，直接贴图，不再给按钮
      const b = document.createElement('button')
      b.className = 'imgchip'
      b.textContent = '🖼 ' + baseNameOf(p) + ' · 点我看图'
      b.onclick = () => loadImage(p, b)
      wrap.appendChild(b)
    }
    if (wrap.childNodes.length) d.appendChild(wrap)
  }
  for (const p of paths) {
    const hit = S.imgCache[p]
    if (!hit) continue
    const img = document.createElement('img')
    img.className = 'msgimg'
    img.src = hit.url
    img.alt = hit.name
    d.appendChild(img)
  }
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

// 记下「这条 cmdId 是哪个新功能发的」，失败时才能给出有用的提示
function nextCmdIdFor(name) {
  const id = nextCmdId()
  S.cmdNames[id] = name
  return id
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

/* ================= 请求/回执（req → ev.result 一对一） ================= */
/*
 * 手机发的命令全是「发出去就完事」的（fire-and-forget），唯一的回执面是主机回的
 * `ev.result`。这个函数把「发 → 等回执 → 超时判失败」收成一颗 Promise：
 * 看图分块用它，会话列表刷新也用它（2026-11-12：刷新按钮原来没有回执也没有超时，
 * 链路半死时点了永远没反应 —— 见 refreshSessions 里的根因注释）。
 * 时序：sendSealed 发出去，回执在 applyEvent 的 ev.result 里按 cmdId 结算。
 */
const IMG_CMD_TIMEOUT_MS = 20000
// 240 × 256KB ≈ 60MB，主机侧上限 20MB，留足余量（主要防主机回next 写错时死循环）
const IMG_MAX_CHUNKS = 240

function requestAck(payload, timeoutMs) {
  return new Promise((resolve) => {
    const id = payload.cmdId
    const timer = setTimeout(() => {
      delete S.ackWaiters[id]
      delete S.cmdNames[id]   // 超时了就把标记一起清掉：迟到的那条回执不该再按"功能名"给提示
      resolve({ ok: false, message: '主机没回应（超时）' })
    }, timeoutMs || IMG_CMD_TIMEOUT_MS)
    S.ackWaiters[id] = (res) => {
      clearTimeout(timer)
      delete S.ackWaiters[id]
      resolve(res)
    }
    sendSealed(payload)
  })
}

function baseNameOf(p) {
  const parts = String(p || '').split(/[\\/]/)
  return parts[parts.length - 1] || '图片'
}

// requester 是注入点（自测用）：不传就走真的 requestAck
async function loadImage(path, btn, requester) {
  if (S.imgBusy[path]) return
  if (S.imgCache[path]) return   // 已经取过（renderMessages 会直接贴出来）
  S.imgBusy[path] = true
  const oldText = btn ? btn.textContent : ''
  const parts = []
  let offset = 0
  let mime = 'image/png'
  let total = 0
  let name = baseNameOf(path)
  try {
    for (let i = 0; i < IMG_MAX_CHUNKS; i++) {
      if (btn) btn.textContent = '取图中… ' + (total ? Math.min(99, Math.round((offset / total) * 100)) + '%' : '')
      const ask = requester || requestAck
      const res = await ask({
        t: 'cmd.file_image',
        cmdId: nextCmdId(),
        path,
        ...(offset ? { offset } : {}),
      })
      if (!res.ok) throw new Error(res.message || '取图失败')
      const d = res.data && typeof res.data === 'object' ? res.data : {}
      if (d.kind !== 'image') throw new Error('主机回的不是图片块（主机插件版本太旧？）')
      if (i === 0) {
        mime = d.mime || mime
        name = d.name || name
        total = Number(d.size) || 0
      }
      const bytes = b64d(String(d.data || ''))
      if (bytes.length) parts.push(bytes)
      if (d.next === undefined || d.next === null) break
      offset = Number(d.next) || 0
      if (!offset) throw new Error('主机的分块偏移不合法')
    }
    if (!parts.length) throw new Error('这张图是空的')
    const url = URL.createObjectURL(new Blob(parts, { type: mime }))
    S.imgCache[path] = { url, name, bytes: total }
    renderMessages()
    setStatus('图已取到（' + Math.max(1, Math.round(total / 1024)) + 'KB）', '#3ecf8e')
  } catch (e) {
    const msg = e && e.message ? e.message : String(e)
    log('[看图] ' + msg)
    setStatus(msg.slice(0, 42), '#ff5c7a')
    // 状态栏那条会被 run_state 立刻覆盖（表现就是「点一下只闪一下」），原因必须留在按钮上
    const hint = /不支持|认不出|升级/.test(msg) ? '主机插件还是旧版，重启 DSH 后再点' : msg
    if (btn) btn.textContent = '⚠️ ' + hint.slice(0, 26) + '（点我再试）'
  } finally {
    S.imgBusy[path] = false
  }
}

function cmdListSessions() {
  sendSealed({ t: 'cmd.list_sessions', cmdId: nextCmdId() })
}

/* ================= 「刷新」按钮：发出去要有回音 ================= */
/*
 * 2026-11-12 的根因（真机取证，见报告）：**不是**按钮被挡住，也不是点击区域太小 ——
 * headless 里 `elementFromPoint` 打中的就是 refreshBtn 本身，46×40 css px 完全可点。
 * 是这条链路三处都「不吭声」：
 *   1. 原来一句 `if (S.paired) cmdListSessions()`：fire-and-forget —— `nextCmdId()`
 *      不登记回执、没有超时、也不看 p.ok，主机不回就永远没下文；
 *   2. 成功时屏幕上**没有任何变化**（列表本来就长那样），"刷新成功"和"按钮是死的"
 *      在视觉上完全一样 —— 用户当然判定它没反应；
 *   3. 失败路径全静默：`!S.paired` 直接 return；socket 不是 open 时 `sendRaw`
 *      只往默认收起的日志栏写一行；而 Android WebView 退到后台后最常见的形态是
 *      **半开 socket**（TCP 没关、readyState 还是 1，发出去石沉大海），
 *      这种状态下所有命令都发得出去、一个回执都回不来，且永远不会触发 onclose。
 *   唯一的"恢复"方式于是变成退出 App 重进 —— 那会重建 socket、重新拉列表。
 * 所以这里补三件事：可等待的回执（requestAck）+ 按钮/状态栏可见反馈 + 链路活性判断。
 */
const LIST_ACK_TIMEOUT_MS = 10000
/** 25 秒一次心跳，连丢三拍还没有任何入帧就判链路已死（半开连接只有主动掐才能恢复）。 */
const LINK_SILENT_MS = 75000

function fmtClock(ts) {
  const d = new Date(ts || Date.now())
  const p = (n) => String(n).padStart(2, '0')
  return p(d.getHours()) + ':' + p(d.getMinutes())
}

/** 时间 → 「刚刚 / 3 分钟前 / 2 小时前 / 11-09」；空值给空串。 */
function fmtAgo(t) {
  if (!t) return ''
  const ms = typeof t === 'number' ? t : Date.parse(t)
  if (!isFinite(ms)) return ''
  const d = Date.now() - ms
  if (d < 60e3) return '刚刚'
  if (d < 3600e3) return Math.floor(d / 60e3) + ' 分钟前'
  if (d < 86400e3) return Math.floor(d / 3600e3) + ' 小时前'
  if (d < 7 * 86400e3) return Math.floor(d / 86400e3) + ' 天前'
  const dt = new Date(ms)
  return (dt.getMonth() + 1) + '-' + String(dt.getDate()).padStart(2, '0')
}

function setRefreshBtn(text) {
  const btn = el.refreshBtn
  if (!btn) return
  btn.disabled = S.refreshBusy
  btn.textContent = text || '刷新'
}

function setListMeta(text) {
  if (el.listMeta) el.listMeta.textContent = text || ''
}

/** 半开连接/发送失败：别装作没发生——立刻告诉用户，并主动重建连接。 */
function noteLinkDead(why) {
  const now = Date.now()
  if (now < (S.deadAt || 0)) return false
  S.deadAt = now + 15000      // 15 秒内不重复触发（几个命令同时失败时只重连一次）
  log('[链路] ' + why + '：判定连接已死，主动重连')
  S.reconnectTries = 0
  stopReconnect()
  const old = S.ws
  S.ws = null                 // 让 sendRaw 立刻知道发不出去
  try { if (old) old.close() } catch (_) {}
  connect()
  return false
}

/**
 * 链路活性：`readyState === 1` 不代表对面还活着（半开连接）。
 * 判据只用"多久没收到任何帧"，因为心跳 25 秒一次、pong 也走同一根线。
 */
function checkLinkAlive() {
  if (!S.paired) return true
  const ws = S.ws
  if (!ws || ws.readyState !== 1) return true   // 真断了由 onclose 那条路负责
  const since = Date.now() - (S.lastInbound || Date.now())
  if (since < LINK_SILENT_MS) return true
  setStatus('连接像是断了，正在重连…', '#e0a83a')
  setListMeta('连接像是断了，正在重连…')
  noteLinkDead(Math.round(since / 1000) + ' 秒没收到任何帧')
  return false
}

/**
 * 刷新会话列表：按钮必须给出可见反馈，失败要说出来，成功也要有"刚更新"的痕迹。
 * @param {{silent?: boolean}} opts silent = 回前台自动刷（不改按钮文案，但仍会报错）
 */
async function refreshSessions(opts) {
  const silent = !!(opts && opts.silent)
  if (S.refreshBusy) return false
  if (!S.ws || S.ws.readyState !== 1) {
    setStatus('连接断了，正在重连…', '#ff5c7a')
    setListMeta('连接断了，正在重连…')
    noteLinkDead('发送前发现连接不在')   // 它内部会 connect()；万一又失败，由 onclose 那条退避接管
    return false
  }
  if (!S.paired || !S.kC2H) {
    setStatus('还没连上电脑，先配对', '#e0a83a')
    setListMeta('还没连上电脑')
    return false
  }
  S.refreshBusy = true
  if (!silent) setRefreshBtn('刷新中…')
  const res = await requestAck({ t: 'cmd.list_sessions', cmdId: nextCmdIdFor('list') }, LIST_ACK_TIMEOUT_MS)
  S.refreshBusy = false
  if (res.ok) {
    const n = S.sessions.length
    setRefreshBtn('已更新')
    setListMeta('已更新 ' + fmtClock(S.listStamp || Date.now()) + ' · ' + n + ' 条会话')
    setStatus('列表已更新（' + n + ' 条）', '#3ecf8e')
    setTimeout(() => { if (!S.refreshBusy) setRefreshBtn('刷新') }, 1500)
    return true
  }
  const msg = String(res.message || '刷新失败').slice(0, 40)
  setRefreshBtn('再试')
  setListMeta('刷新失败：' + msg)
  setStatus('刷新失败：' + msg, '#ff5c7a')
  log('[刷新] ' + msg)
  setTimeout(() => { if (!S.refreshBusy) setRefreshBtn('刷新') }, 2000)
  return false
}

/**
 * 配对/重连后“拉会话列表”是**一次性**请求：帧丢了（刚配对时 socket 切换、relay 抖动）
 * 就永远停在加载中。这里在没拿到列表时每 2.5 秒重发，最多 5 次。
 */
let sessionListRetry = 0
function ensureSessionList(tries = 0) {
  if (S.sessions.length > 0 || tries >= 5) return
  if (!S.paired) return
  setTimeout(() => {
    if (!S.paired || S.sessions.length > 0) return
    cmdListSessions()
    ensureSessionList(tries + 1)
  }, 2500)
}

/* ================= 新建会话（指定工作区） ================= */
// 同工作区里已经有一个空的（没标题、没在跑）会话时，直接进去，别再建新的 ——
// 否则连点几次 ＋ 就会在列表里堆一堆「新会话」
function findEmptySession(ws) {
  const key = ws || ''
  for (const raw of S.sessions) {
    const s = raw && raw.session ? raw.session : raw
    if (!s) continue
    if ((s.workspace || '') !== key) continue
    const id = s.id || s.sessionId || ''
    if (!id) continue
    if (typeof s.title === 'string' && s.title.trim()) continue
    if (S.running[id]) continue
    if (s.blank === false) continue
    return id
  }
  return null
}
function cmdNewSession(workspace) {
  if (!S.kC2H) { log('还没配对'); return }
  if (S.newBusy) { setStatus('正在新建，稍等…', '#e0a83a'); return }
  const reuse = findEmptySession(workspace)
  if (reuse) {
    log('[新建会话] 已有空会话，直接进 ' + reuse)
    S.fresh[reuse] = true
    openSession(reuse, '新会话')
    return
  }
  S.newBusy = true
  setStatus('新建会话…', '#5b8cff')
  log('[新建会话] ' + (workspace || '默认工作区'))
  renderSessions()   // 立刻把按钮改成「建中…」，别让人以为没点上
  sendSealed({ t: 'cmd.new_session', cmdId: nextCmdIdFor('new_session'), ...(workspace ? { workspace } : {}) })
  clearTimeout(S.newBusyTimer)
  S.newBusyTimer = setTimeout(() => {
    if (!S.newBusy) return
    S.newBusy = false
    renderSessions()
    setStatus('新建超时，稍后再试', '#e0a83a')
  }, 20000)
}
function clearNewBusy() {
  if (!S.newBusy) return
  S.newBusy = false
  clearTimeout(S.newBusyTimer)
  renderSessions()
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
  sendSealed({ t: 'cmd.rename_session', cmdId: nextCmdIdFor('rename'), sessionId: S.current, title })
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
    S.modelErr = ''
    sendSealed({ t: 'cmd.get_models', cmdId: nextCmdIdFor('models') })
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
    t: 'cmd.set_model', cmdId: nextCmdIdFor('set_model'), sessionId: S.current,
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
    d.textContent = S.modelErr
      ? '取不到清单：' + S.modelErr
      : (S.catalog ? '这台电脑上没有可用模型' : '正在取模型清单…')
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

/**
 * 历史第一页的条数。协议上限就是 200（`cmd.session_history.limit` 的 schema），
 * 主机那边还有一条 10 万字符的页预算，超了会少给条目、但在 `nextBeforeSeq` 里
 * 留一个「还有更早」的游标，所以这一页给不满也不用兜底逻辑。
 */
const HISTORY_PAGE_LIMIT = 200

/** 组一条历史请求。纯函数，方便自测；`beforeSeq` 不传就是「最新一页」。 */
function historyCmd(sessionId, beforeSeq) {
  return {
    t: 'cmd.session_history',
    cmdId: nextCmdId(),
    sessionId,
    limit: HISTORY_PAGE_LIMIT,
    ...(beforeSeq === undefined ? {} : { beforeSeq }),
  }
}

/** 「加载更早」按钮的显隐跟着游标走；翻页请求在飞的时候先藏起来（防连点）。 */
function syncEarlierBtn() {
  const wrap = el.earlierWrap
  if (!wrap) return
  wrap.hidden = !S.nextBeforeSeq || S.earlierBusy
}

/** 点「加载更早」：带上主机给的游标，再要一页更早的。 */
function loadEarlier() {
  if (!S.current || S.earlierBusy || S.nextBeforeSeq === undefined) return
  // 没连上就别发：发了也没人回，而按钮会因为 earlierBusy 一直藏着
  if (!S.paired || !S.ws || S.ws.readyState !== 1) return
  S.earlierBusy = true
  syncEarlierBtn()
  sendSealed(historyCmd(S.current, S.nextBeforeSeq))
}

/* ================= 会话缓存（本地先显示，再向主机刷新） ================= */
/*
 * 从列表点进一条会话时，先拿 localStorage 里上次见过的消息把列表铺出来
 * （离线也看得到），再发 cmd.session_history 让主机把最新一页盖回来。
 * 上限按会话条数 + 总字符双闸：单条消息最长 2 万字，只按条数算能把 5MB 配额打满。
 */
const CACHE_PREFIX = 'drc.cache.'
const CACHE_MAX_SESSIONS = 6
const CACHE_MAX_MSGS = 300
const CACHE_MAX_CHARS = 300_000
let cacheTimer = 0
let runTicker = 0

function cacheKey(id) { return CACHE_PREFIX + id }

function readCache(id) {
  try {
    const raw = localStorage.getItem(cacheKey(id))
    if (!raw) return null
    const box = JSON.parse(raw)
    if (!box || !Array.isArray(box.msgs)) return null
    return box
  } catch (_) { return null }
}

/** 存一份会话快照：只留最近的、非工具行的消息，超字符预算就从最旧开始丢。 */
function saveCache(id, msgs) {
  if (!id || !Array.isArray(msgs)) return
  const keep = []
  let chars = 0
  for (let i = msgs.length - 1; i >= 0 && keep.length < CACHE_MAX_MSGS; i--) {
    const m = msgs[i]
    if (!m || m.kind === 'tool') continue
    const text = String(m.text || '')
    if (chars + text.length > CACHE_MAX_CHARS && keep.length > 0) break
    keep.unshift(m)
    chars += text.length
  }
  const box = { at: Date.now(), msgs: keep }
  try {
    localStorage.setItem(cacheKey(id), JSON.stringify(box))
    pruneCaches(id, false)
  } catch (_) {
    // 配额满了：先清别人的缓存，再存一次自己的
    pruneCaches(id, true)
    try { localStorage.setItem(cacheKey(id), JSON.stringify(box)) } catch (_) {}
  }
}

function pruneCaches(keepId, wipeOthers) {
  try {
    if (typeof localStorage.key !== 'function') return
    const rows = []
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i)
      if (!k || k.indexOf(CACHE_PREFIX) !== 0 || k === cacheKey(keepId)) continue
      let at = 0
      try { const b = JSON.parse(localStorage.getItem(k)); at = (b && b.at) || 0 } catch (_) {}
      rows.push({ k, at })
    }
    if (wipeOthers) { for (const r of rows) localStorage.removeItem(r.k); return }
    if (rows.length < CACHE_MAX_SESSIONS) return
    rows.sort((a, b) => a.at - b.at)
    while (rows.length >= CACHE_MAX_SESSIONS) { const r = rows.shift(); if (r) localStorage.removeItem(r.k) }
  } catch (_) {}
}

function clearCaches() {
  try {
    if (typeof localStorage.key !== 'function') return
    const keys = []
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i)
      if (k && k.indexOf(CACHE_PREFIX) === 0) keys.push(k)
    }
    for (const k of keys) localStorage.removeItem(k)
  } catch (_) {}
}

function scheduleCacheSave() {
  if (!S.current) return
  // 记下"这条消息属于哪个会话"：500ms 内用户切了会话，不能把新会话的列表写进旧会话的缓存
  const id = S.current
  clearTimeout(cacheTimer)
  cacheTimer = setTimeout(() => { if (S.current === id) saveCache(id, S.msgs) }, 500)
}

/* ================= 运行状态条 + 停止键（灰/亮） ================= */
/*
 * 一条横幅要回答三个问题（2026-11-12 用户：「看不到在干嘛，只能盲等」）：
 *   1. 跑了多久 —— 本地计时（`S.runStart`，第一帧 running 起算）；
 *   2. 跑到哪了 —— 只能用**主机已经发出的加密业务事件**：
 *      `ev.todo`（待办全量快照：完成 x/y、正在做哪条）、`ev.message_delta`
 *      （这一轮已写多少字）、`ev.retry` / `ev.compaction`（重试、压缩上下文）、
 *      `ev.permission_request` / `ev.question_request`（卡在等你）。
 *      **工具步数拿不到**：主机自 2026-10-30 起刻意不把工具细节发到手机
 *      （`kernel-events.ts` 的 `case 'tool'` 只 `noteStep()`），逐步计数只进
 *      `statusDigest`（明文摘要，手机侧拿不到实时值）。所以这里不编造一个"第 N 步"。
 *   3. 停下来了要看得见 —— 从 running → idle 不直接消失，先亮 6 秒「已完成 · 用时 x」。
 */
function fmtElapsed(ms) {
  const total = Math.max(0, Math.floor(ms / 1000))
  return Math.floor(total / 60) + ':' + String(total % 60).padStart(2, '0')
}

/** 本轮进展的一句话摘要：只用真实事件，"正在：…"来自待办里 in_progress 那条。 */
function runProgressText(id) {
  const st = S.step[id] || {}
  const now = Date.now()
  const bits = []
  if (st.gate) bits.push(st.gate)
  if (st.compact) bits.push('压缩上下文')
  if (st.retry && now - (st.retryAt || 0) < 20000) bits.push('重试 ' + st.retry)
  if (st.doing) bits.push('正在：' + st.doing)
  if (st.total) bits.push('待办 ' + (st.done || 0) + '/' + st.total)
  if (st.wrote) bits.push('已写 ' + st.wrote + ' 字')
  return bits.join(' · ')
}

/** 当前会话在跑就显示「深度求索中… m:ss · 进展」并每秒刷新；刚跑完先亮一会儿「已完成」。 */
function updateRunBanner() {
  const box = el.runBanner
  const txt = el.runText
  if (!box || !txt) return
  const id = S.current
  const running = !!(id && S.running[id])
  const done = id ? S.runDone[id] : null
  if (!running && done && Date.now() < done.until) {
    box.hidden = false
    box.classList.add('done')
    txt.textContent = '已完成 · 用时 ' + fmtElapsed(done.ms)
    if (el.runSub) el.runSub.textContent = done.summary || ''
    if (!runTicker) runTicker = setInterval(updateRunBanner, 1000)
    return
  }
  if (!running) {
    box.hidden = true
    box.classList.remove('done')
    if (el.runSub) el.runSub.textContent = ''
    if (runTicker) { clearInterval(runTicker); runTicker = 0 }
    return
  }
  const started = S.runStart[id] || Date.now()
  box.hidden = false
  box.classList.remove('done')
  txt.textContent = '深度求索中… ' + fmtElapsed(Date.now() - started)
  if (el.runSub) el.runSub.textContent = runProgressText(id)
  if (!runTicker) runTicker = setInterval(updateRunBanner, 1000)
}

/** 「停」只在当前会话运行中才亮着，空闲时灰掉（灰了也不能点）。 */
function syncStopBtn() {
  const btn = el.stopBtn
  if (!btn) return
  const running = !!(S.current && S.running[S.current])
  btn.disabled = !running
  btn.classList.toggle('stopOn', running)
  btn.title = running ? '中断本轮' : '当前没有在跑的任务'
}

function openSession(id, title) {
  S.current = id
  S.currentTitle = title || '对话'
  // 先铺本地缓存：断网/慢网也能立刻看到上次的内容；主机那一页回来后会整页覆盖
  const cached = readCache(id)
  S.msgs = cached && Array.isArray(cached.msgs) ? cached.msgs : []
  S.historyLoaded = !!(cached && S.msgs.length)
  S.cards = {}
  S.qSel = {}
  S.lastSent = null
  S.nextBeforeSeq = undefined
  S.earlierBusy = false
  if (el.earlierWrap) el.earlierWrap.hidden = true
  showView('chat')
  renderMessages()
  updateRunBanner()
  syncStopBtn()
  renderSessions()
  refreshModelBadge()
  saveOpenSession(id, title || '')
  sendSealed(historyCmd(id))
  sendSealed({ t: 'cmd.get_pending', cmdId: nextCmdId(), sessionId: id })
}

function goBack() {
  S.current = null
  S.currentTitle = ''
  S.msgs = []
  S.cards = {}
  S.lastSent = null
  S.nextBeforeSeq = undefined
  S.earlierBusy = false
  if (el.earlierWrap) el.earlierWrap.hidden = true
  clearOpenSession()
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
    // 主机主动推的列表就是"新鲜的一份"：记下时间，列表页据此显示"已更新 HH:MM"
    S.listStamp = Date.now()
    renderSessions()
    return
  }
  if (t === 'ev.keep_awake_state') return
  if (t === 'ev.host_info') {
    log('[host] ' + (p.host?.platform || '') + ' ' + (p.host?.pluginVersion || ''))
    return
  }
  if (t === 'ev.result') {
    // 聊天页 5 秒一次的运行态轮询回执：一对一，先在这里结算，别落到下面的功能分流里
    if (S.liveCmd && p.cmdId === S.liveCmd) {
      S.liveCmd = ''
      delete S.cmdNames[p.cmdId]
      const liveData = p.data && typeof p.data === 'object' ? p.data : {}
      const list = Array.isArray(liveData.sessions) ? liveData.sessions : []
      const cur = list.find((row) => row && row.id === S.current)
      if (cur && typeof cur.state === 'string') {
        const runningNow = cur.state === 'running'
        const wasRunning = !!S.running[S.current]
        S.running[S.current] = runningNow
        if (wasRunning && !runningNow) S.fishDoneUntil = Date.now() + 2500
        fishSync()
      }
      return
    }
    // 一对一请求的回执（看图 / 刷新列表）：按 cmdId 结算，别落到下面那套「按功能名分流」的分支里
    const waiter = S.ackWaiters[p.cmdId]
    if (waiter) {
      delete S.cmdNames[p.cmdId]   // 回执到了就把「这条是干嘛的」标记删掉，别让它无限涨
      waiter({ ok: p.ok === true, message: p.message, data: p.data })
      return
    }
    const d = p.data && typeof p.data === 'object' ? p.data : null
    const wanted = S.cmdNames[p.cmdId]
    if (wanted) delete S.cmdNames[p.cmdId]
    if (p.ok === false) {
      log('[result] FAIL ' + (p.message || '') + (wanted ? '（' + wanted + '）' : ''))
      if (wanted === 'models') {
        S.modelErr = p.message || '取不到模型清单'
        renderModelSheet()
      }
      if (wanted === 'new_session') clearNewBusy()
      setStatus(wanted ? '失败：重启 DSH 再试' : String(p.message || '失败了').slice(0, 34), '#e0a83a')
    }
    if (d) {
      // 模型清单（cmd.get_models 的回执）
      if (d.kind === 'catalog' && d.catalog) {
        S.catalog = d.catalog
        S.modelErr = ''
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
          saveOpenSession(S.current, d.title)
        }
        setStatus('已改名', '#3ecf8e')
      }
      // 新建会话成功 → 直接进去
      if (d.sessionId && !d.kind) {
        log('[新建会话] 已创建 ' + d.sessionId)
        clearNewBusy()
        S.fresh[d.sessionId] = true
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
      const runningNow = p.state === 'running'
      // 第一次看到 running 才记开始时间：反复的 running 帧不能把计时器重置
      if (runningNow && !S.running[sid]) {
        S.runStart[sid] = Date.now()
        S.step[sid] = {}          // 新一轮：上一轮的待办/字数不许串进来
      }
      const startedAt = S.runStart[sid]   // 收尾前先取走：下面会把它删掉
      if (!runningNow) delete S.runStart[sid]
      const wasRunning = !!S.running[sid]
      S.running[sid] = runningNow
      S.lastAct[sid] = Date.now()
      if (!wasRunning && runningNow) {
        // 新一轮开始：清掉上一轮的“回答中/完成”窗口，否则会串状态
        S.fishAnswerUntil = 0
        S.fishDoneUntil = 0
        delete S.runDone[sid]
      }
      if (wasRunning && !runningNow) {
        // 跑完了：留一条 6 秒的「已完成 · 用时 x」——状态从「运行中」直接跳回
        // 「空闲」时用户分不清"跑完"和"没跑过"，这条过渡就是给眼睛的交代。
        const spent = Date.now() - (startedAt || Date.now())
        const summary = runProgressText(sid) || (p.detail === 'agent-error' ? '出错了' : '')
        S.runDone[sid] = { at: Date.now(), until: Date.now() + RUN_DONE_FLASH_MS, ms: spent, summary }
        S.step[sid] = {}
        S.fishDoneUntil = Date.now() + 2500
        if (S.current === sid) S.fishAnswerUntil = 0
        setTimeout(() => {
          const rec = S.runDone[sid]
          if (rec && Date.now() >= rec.until) {
            delete S.runDone[sid]
            renderSessions()
            updateRunBanner()
          }
        }, RUN_DONE_FLASH_MS + 120)
      }
      fishSync()
      renderSessions()
      if (S.current === sid) setStatus(runningNow ? '运行中…' : '空闲', runningNow ? '#3ecf8e' : '#8a8aa0')
    } else if (S.current === null) {
      setStatus(p.state === 'running' ? '运行中…' : '空闲', p.state === 'running' ? '#3ecf8e' : '#8a8aa0')
    }
    updateRunBanner()
    syncStopBtn()
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
          // 空正文的用户帧同样不建气泡（纯图片的 splice 之类）
          if (!text) break
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
      const deltaText = typeof p.delta === 'string' ? p.delta : ''
      let m = S.msgs.find(x => x.id === mid && x.kind !== 'tool')
      if (!m) {
        // 空正文的帧**不建气泡**：工具步一步正文都没出时主机会补一帧「只收尾」的空 delta，
        // 而工具行已经不往手机同步了 —— 这种帧建出来就是一条永远空着的气泡。
        // 收尾不需要气泡：运行态由 ev.run_state 管，进度在状态栏。
        if (!deltaText) break
        m = { id: mid, kind: 'msg', role: p.role || 'assistant', text: '' }
        S.msgs.push(m)
      }
      if (deltaText) m.text += deltaText
      if (p.role) m.role = p.role
      if (p.done) m.done = true
      S.fishTalkUntil = Date.now() + 2500
      S.fishAnswerUntil = Date.now() + 3000
      S.lastAct[sid || S.current] = Date.now()
      // "跑到哪了"的一面镜子：这一轮正文已经写出来多少字（流式增长 = 活着）
      if (deltaText && m.role !== 'user') {
        const st = S.step[sid || S.current] || (S.step[sid || S.current] = {})
        st.wrote = m.text.length
      }
      fishSync()
      updateRunBanner()
      scheduleRender()
      break
    }
    case 'ev.tool_event': {
      // 主机从 2026-10-30 起不再往手机发工具细节（见 kernel-events.ts 的 case 'tool'），
      // 这段只在老主机上才会走到：仍然渲染，但别指望它来数步数。
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
      const st = S.step[sid || S.current] || (S.step[sid || S.current] = {})
      st.gate = '等你审批'
      renderMessages()
      updateRunBanner()
      log('收到审批请求：' + (p.action || ''))
      break
    }
    case 'ev.question_request': {
      if (!p.requestId) break
      S.cards[p.requestId] = { sessionId: sid || S.current, kind: 'q', payload: p }
      const st = S.step[sid || S.current] || (S.step[sid || S.current] = {})
      st.gate = '等你回答'
      renderMessages()
      updateRunBanner()
      log('收到提问')
      break
    }
    case 'ev.permission_resolved':
    case 'ev.question_resolved': {
      if (p.requestId && S.cards[p.requestId]) {
        delete S.cards[p.requestId]
        delete S.qSel[p.requestId]
        const st = S.step[sid || S.current]
        if (st) st.gate = ''
        renderMessages()
        updateRunBanner()
      }
      break
    }
    case 'ev.session_history': {
      // 用户可能已经切到别的会话了：这一页对不上就不往当前列表里塞
      if (p.sessionId && S.current && p.sessionId !== S.current) break
      const items = Array.isArray(p.items) ? p.items : []
      const earlier = S.earlierBusy
      const main = el.main
      // 翻更早的页时，把回放进来的条目先装进一个临时列表，再拼到现有消息前面：
      // 直接往 S.msgs 里塞会跑到末尾，而且和已经有的条目（翻页边界重叠）会重复。
      const prevMsgs = earlier ? S.msgs : null
      const prevHeight = earlier && main ? main.scrollHeight : 0
      const prevTop = earlier && main ? main.scrollTop : 0
      const pendingKeep = earlier ? [] : S.msgs.filter((m) => m.pending)
      if (earlier) S.msgs = []
      else { S.msgs = []; S.historyLoaded = true }
      S.replaying = true
      for (const it of items) applyEvent(it)
      S.replaying = false
      if (!earlier) {
        // 刚发出去、主机还没回执的那条不能被历史页吞掉
        for (const m of pendingKeep) if (!S.msgs.some((x) => x.id === m.id)) S.msgs.push(m)
      }
      if (earlier && prevMsgs) {
        const seen = {}
        for (const m of prevMsgs) seen[m.id] = true
        S.msgs = S.msgs.filter((m) => !seen[m.id]).concat(prevMsgs)
      }
      S.nextBeforeSeq = typeof p.nextBeforeSeq === 'number' ? p.nextBeforeSeq : undefined
      S.earlierBusy = false
      renderMessages()
      syncEarlierBtn()
      // 顶上插了一页，要还原来「看着同一行」的滚动位置，否则会瞬间跳到会话开头。
      if (main && earlier) main.scrollTop = prevTop + (main.scrollHeight - prevHeight)
      break
    }
    case 'ev.todo': {
      // 待办不往消息流里塞（会和正文抢版面），但它是「这一轮在干什么」的**唯一**
      // 结构化线索：完成 x/y + 正在做哪条 → 运行横幅的第二行。
      const todos = Array.isArray(p.todos) ? p.todos : []
      const st = S.step[sid || S.current] || (S.step[sid || S.current] = {})
      st.total = todos.length
      st.done = todos.filter((x) => x && x.status === 'completed').length
      const doing = todos.find((x) => x && x.status === 'in_progress') ||
        todos.find((x) => x && x.status === 'pending')
      st.doing = doing && doing.content ? String(doing.content).slice(0, 24) : ''
      S.lastAct[sid || S.current] = Date.now()
      updateRunBanner()
      break
    }
    case 'ev.retry': {
      const st = S.step[sid || S.current] || (S.step[sid || S.current] = {})
      st.retry = p.attempt + '/' + p.max
      st.retryAt = Date.now()
      updateRunBanner()
      log('[重试] ' + p.attempt + '/' + p.max + (p.reason ? ' ' + p.reason : ''))
      break
    }
    case 'ev.compaction': {
      const st = S.step[sid || S.current] || (S.step[sid || S.current] = {})
      st.compact = p.state === 'started'
      updateRunBanner()
      if (S.current === sid || !sid) setStatus('压缩上下文 ' + p.state, p.state === 'failed' ? '#ff5c7a' : '#e0a83a')
      break
    }
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
  // 链路活性：任何入帧（含 pong / ping / enc）都算"对面还活着"
  S.lastInbound = Date.now()
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
        if (S.current) {
          // 断线重连时**不要**把人踢回列表：原来这里把 current 清空 + showView('list')，
          // 于是手机放一会儿、网络抖一下、主机重启一次，用户就莫名"闪退"回会话列表。
          // 现在留在原会话里：重拉一遍历史和未决交互，页面不跳。
          log('重连：留在当前会话 ' + S.current)
          S.historyLoaded = false
          S.lastSent = null
          S.replaying = false
          showView('chat')
          renderMessages()
          sendSealed(historyCmd(S.current))
          sendSealed({ t: 'cmd.get_pending', cmdId: nextCmdId(), sessionId: S.current })
          cmdListSessions()
          ensureSessionList()
        } else {
          // 页面重载/App 重进：上次开着会话就回到那条，别一进来就是列表
          const saved = loadOpenSession()
          if (saved) {
            log('恢复上次打开的会话 ' + saved.id)
            openSession(saved.id, saved.title || '对话')
          } else {
            S.msgs = []
            S.cards = {}
            showView('list')
            renderSessions()
          }
          cmdListSessions()
          ensureSessionList()
        }
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
  ensureSessionList()
  sendSealed({ t: 'cmd.get_pending', cmdId: nextCmdId() })
}

/* ================= 启动 ================= */
// 原生更新流程的每一步会推到这里：写进日志栏，并让状态栏实时可见
window.__onUpdateLog = (s) => {
  log('[更新] ' + s)
  setStatus('更新: ' + s, '#e0a83a')
}

/* ================= 小齿轮菜单 / 危险操作确认 ================= */
function toggleMenu() {
  if (!el.menuWrap) return
  el.menuWrap.hidden = !el.menuWrap.hidden
}
function closeMenu() {
  if (el.menuWrap) el.menuWrap.hidden = true
}

// 重新配对是不可逆的（要回家拿新配对码），所以让手指多等 5 秒
function openRepairConfirm() {
  if (!el.confirmWrap) return
  el.confirmWrap.hidden = false
  if (el.cfTitle) el.cfTitle.textContent = '真的要重新配对？'
  if (el.cfText) {
    el.cfText.textContent =
      '断开后这台手机就控制不了电脑了，得回到家、在电脑上点开远控拿到新的 6 位配对码才能再连上。'
  }
  let left = 5
  const tick = () => {
    if (!el.cfOk) return
    if (left > 0) {
      el.cfOk.disabled = true
      el.cfOk.textContent = '要等 ' + left + ' 秒'
      left--
      S.cfTimer = setTimeout(tick, 1000)
    } else {
      el.cfOk.disabled = false
      el.cfOk.textContent = '确定重新配对'
    }
  }
  clearTimeout(S.cfTimer)
  tick()
}
function closeRepairConfirm() {
  clearTimeout(S.cfTimer)
  S.cfTimer = 0
  if (el.confirmWrap) el.confirmWrap.hidden = true
  if (el.cfOk) { el.cfOk.disabled = true; el.cfOk.textContent = '要等 5 秒' }
}

// 真正断开、回到配对页
function doRepairPair() {
  clearSession()
  stopReconnect()
  stopPing()
  try { S.ws?.close() } catch (_) {}
  S.ws = null
  S.mode = 'pair'
  S.paired = false
  showView('pair')
  setStatus('请输入新的配对码')
}


/* ================= 悬浮大肥鱼（占位形象，0.9.x） ================= */
/*
 * 目标形态是「形象住进手机 App」：一只可拖动的鲸鱼常年浮在界面上，
 * 电脑端在跑活时它会晃、点一下放个小气泡。现在用的是**占位画**（内联 SVG），
 * 等真素材（帧图）到了只换 #fishBody 里的内容，交互和状态全不用动。
 *
 * 状态：
 *   off   —— 没配对 / 不在会话页（看不见）
 *   away  —— 主机暂时离线（半透明、去色）
 *   think —— 当前会话在跑（上下晃）
 *   idle  —— 在线空闲（呼吸 + 偶尔眨眼）
 */
const FISH_POS_KEY = 'drc.fishPos'
const FISH_SIZE = 64
const FISH_TAP_SLOP = 8
/** 空闲多久之后躺下睡（Nap）。90 秒：够短到"人走开一会儿"就能歇，够长到不打断小互动。 */
const FISH_NAP_AFTER_MS = 90_000
let fishDrag = null
let fishBubbleTimer = 0

function readFishPos() {
  try {
    const raw = localStorage.getItem(FISH_POS_KEY)
    const pos = raw ? JSON.parse(raw) : null
    if (pos && Number.isFinite(pos.x) && Number.isFinite(pos.y)) return { x: pos.x, y: pos.y }
  } catch (_) {}
  return null
}

function clampFish(x, y) {
  const w = document.documentElement.clientWidth || window.innerWidth || 360
  const h = window.innerHeight || document.documentElement.clientHeight || 640
  const maxX = Math.max(8, w - FISH_SIZE - 8)
  const maxY = Math.max(8, h - FISH_SIZE - 8 - 72)   // 别压在输入框上
  return { x: Math.min(Math.max(8, x), maxX), y: Math.min(Math.max(8, y), maxY) }
}

function placeFish(x, y, persist) {
  const fab = el.fishFab
  if (!fab) return
  const p = clampFish(x, y)
  fab.style.left = p.x + 'px'
  fab.style.top = p.y + 'px'
  if (el.fishBubble) el.fishBubble.classList.toggle('left', p.x < 120)
  if (persist) {
    try { localStorage.setItem(FISH_POS_KEY, JSON.stringify(p)) } catch (_) {}
  }
}

function fishState() {
  if (!S.paired) return 'off'
  if (S.hostAway) return 'away'
  const now = Date.now()
  if (S.fishPokeUntil && now < S.fishPokeUntil) return 'poke'
  if (hostRunning()) {
    // 卡在等你动手（审批/提问）时别装成"还在思考"
    if (fishGated()) return 'wait'
    if (S.fishAnswerUntil && now < S.fishAnswerUntil) return 'talk'
    return 'think'
  }
  if (S.fishDoneUntil && now < S.fishDoneUntil) return 'done'
  if (S.fishTalkUntil && now < S.fishTalkUntil) return 'talk'
  // 闲了很久没人理 → 躺下睡（Nap），别一直原地晃
  if (S.fishIdleSince && now - S.fishIdleSince > FISH_NAP_AFTER_MS) return 'nap'
  return 'idle'
}

/** 主机上是否有会话在跑（不只盯当前这一条）：列表页也看得出"电脑在干活"。 */
function hostRunning() {
  for (const id in S.running) if (S.running[id]) return true
  return false
}

/** 当前会话是不是卡在一张等人点的卡上（审批 / 提问）。 */
function fishGated() {
  const id = S.current
  if (!id) return false
  for (const rid in S.cards) {
    const c = S.cards[rid]
    if (c && (!c.sessionId || c.sessionId === id)) return true
  }
  return false
}/*
 * 真素材挂载：
 *   1) assets/fish/dafeiyu_<Action>.webp —— 序列帧图集（8 列 × 6 行 = 48 帧），
 *      七套全在（Idle / Think / Talk / Dance / Nap / EatRice / Tsundere），
 *      逐帧播放靠 background-position 推进，不读外部 json（WebView 里 fetch file:// 会被拦）。
 *   2) 图集没到（老包/素材缺失）就退回内联 SVG 占位画，交互/状态不受影响。
 * 注：`fish/idle.png`、`fish/think.png` 是更早的占位单图，`#fishImg` 现在恒隐藏 ——
 * 真素材齐了之后不该再被它们顶替（否则会看到"占位小鱼"而不是鲸鱼娘）。
 */
const FISH_CELL = { w: 60, h: 80 }
const FISH_SPRITES = {
  idle: { file: 'fish/dafeiyu_Idle.webp', cols: 8, rows: 6, frameCount: 48, fps: 24 },
  think: { file: 'fish/dafeiyu_Think.webp', cols: 8, rows: 6, frameCount: 48, fps: 24 },
  talk: { file: 'fish/dafeiyu_Talk.webp', cols: 8, rows: 6, frameCount: 48, fps: 24 },
  nap: { file: 'fish/dafeiyu_Nap.webp', cols: 8, rows: 6, frameCount: 48, fps: 24 },
  eat: { file: 'fish/dafeiyu_EatRice.webp', cols: 8, rows: 6, frameCount: 48, fps: 24 },
  tsundere: { file: 'fish/dafeiyu_Tsundere.webp', cols: 8, rows: 6, frameCount: 48, fps: 24 },
  dance: { file: 'fish/dafeiyu_Dance.webp', cols: 8, rows: 6, frameCount: 48, fps: 24 },
}
let fishSpriteId = 'idle'
const fishSpriteReady = {}
/*
 * 状态 → 动作池（2026-11-12 对齐用户要求）：
 *   连上/空闲 = Idle 或 Nap（eat 是干饭梗，留着当低频彩蛋）
 *   主机在跑 = **只** Think（原来是 think 60 + eat 25，"在跑的时候在吃白饭"很出戏）
 *   收到流式回复 = **只** Talk（原来会随机跳 Dance/Tsundere，正文在流却开始跳舞很怪）
 *   一轮结束 = Dance、被点 = Tsundere、等太久 = Nap —— 这三条在 fishSync 里直连，不进池子。
 */
const FISH_POOLS = {
  idle: [
    { id: 'idle', weight: 60, loops: 2 },
    { id: 'nap', weight: 25, loops: 2 },
    { id: 'eat', weight: 15, loops: 1 },
  ],
  think: [
    { id: 'think', weight: 1, loops: 1 },
  ],
  talk: [
    { id: 'talk', weight: 1, loops: 1 },
  ],
}
let fishStateKey = ''
let fishClipId = ''
let fishClipUntil = 0
let fishSpriteRaf = 0
let fishSpriteStartedAt = 0

/** 时间（毫秒）→ 帧号，纯函数，方便无头自测；到结尾回绕。 */
function fishFrameAt(ms) {
  const spec = FISH_SPRITES[fishSpriteId] || FISH_SPRITES.idle
  const total = spec.frameCount
  const frame = Math.floor((ms / 1000) * spec.fps)
  return ((frame % total) + total) % total
}
/** 帧号 → 图集里的 background-position，纯函数。 */
function fishSpriteOffset(frame) {
  const spec = FISH_SPRITES[fishSpriteId] || FISH_SPRITES.idle
  const col = frame % spec.cols
  const row = Math.floor(frame / spec.cols)
  return { x: -col * FISH_CELL.w, y: -row * FISH_CELL.h }
}
function paintFishSpriteFrame(frame) {
  const sprite = el.fishSprite
  if (!sprite || !fishSpriteReady[(FISH_SPRITES[fishSpriteId] || FISH_SPRITES.idle).file]) return
  const p = fishSpriteOffset(frame)
  sprite.style.backgroundPosition = p.x + 'px ' + p.y + 'px'
}

function stopFishSpriteLoop() {
  if (fishSpriteRaf) cancelAnimationFrame(fishSpriteRaf)
  fishSpriteRaf = 0
}

function startFishSpriteLoop() {
  if (fishSpriteRaf || !fishSpriteReady[(FISH_SPRITES[fishSpriteId] || FISH_SPRITES.idle).file]) return
  fishSpriteStartedAt = (typeof performance !== 'undefined' ? performance.now() : Date.now())
  let lastFrame = -1
  const tick = () => {
    const sprite = el.fishSprite
    if (!sprite || sprite.hidden) { fishSpriteRaf = 0; return }
    const now = (typeof performance !== 'undefined' ? performance.now() : Date.now())
    const frame = fishFrameAt(now - fishSpriteStartedAt)
    if (frame !== lastFrame) {
      lastFrame = frame
      paintFishSpriteFrame(frame)
    }
    fishSpriteRaf = requestAnimationFrame(tick)
  }
  fishSpriteRaf = requestAnimationFrame(tick)
}

function loadFishArt() {
  const check = (src) => new Promise((resolve) => {
    const probe = new Image()
    probe.onload = () => { fishSpriteReady[src] = true; resolve(true) }
    probe.onerror = () => { fishSpriteReady[src] = false; resolve(false) }
    probe.src = src
  })
  const jobs = Object.values(FISH_SPRITES).map((spec) => check(spec.file))
  void Promise.all(jobs).then(() => { fishSync() })
}
function paintFishArt(state) {
  const sprite = el.fishSprite
  const img = el.fishImg
  const svg = el.fishBody && el.fishBody.querySelector('.fishSvg')
  const spec = FISH_SPRITES[state] || FISH_SPRITES.idle
  fishSpriteId = FISH_SPRITES[state] ? state : 'idle'
  const spriteOn = fishSpriteReady[spec.file] === true
  if (sprite) {
    sprite.hidden = !spriteOn
    if (spriteOn) {
      sprite.style.backgroundImage = 'url("' + spec.file + '")'
      sprite.style.backgroundSize = (spec.cols * FISH_CELL.w) + 'px ' + (spec.rows * FISH_CELL.h) + 'px'
      startFishSpriteLoop()
    } else {
      stopFishSpriteLoop()
      sprite.style.backgroundPosition = ''
    }
  }
  if (img) img.hidden = true
  if (svg) svg.style.display = spriteOn ? 'none' : ''
}
function fishBubbleText() {
  if (!S.paired) return '还没连上电脑'
  if (S.hostAway) return '主机暂时离线，等等吧'
  const state = fishState()
  if (state === 'poke') return '唔…别戳啦'
  if (state === 'wait') return '等你点一下'
  if (state === 'think') return '思考中…'
  if (state === 'talk') return '在回答啦'
  if (state === 'done') return '答完啦'
  if (state === 'nap') return '我先躺会儿'
  return '空闲'
}
function fishSync() {
  const fab = el.fishFab
  if (!fab) return
  const visible = S.paired && S.view !== 'pair'
  fab.hidden = !visible
  if (!visible) return
  const state = fishState()
  fab.classList.toggle('think', state === 'think')
  fab.classList.toggle('away', state === 'away')

  // 「闲了多久」：睡觉判定用的时钟；一有活就清零
  if (state === 'think' || state === 'talk' || state === 'poke' || state === 'done' || state === 'wait') {
    S.fishIdleSince = 0
  } else if (!S.fishIdleSince) {
    S.fishIdleSince = Date.now()
  }

  let spriteId
  if (state === 'poke') {
    spriteId = 'tsundere'          // 被点：傲娇
  } else if (state === 'wait') {
    spriteId = 'tsundere'          // 卡在你手上：抱臂等你点
  } else if (state === 'done') {
    spriteId = 'dance'             // 一轮结束：跳一段
  } else if (state === 'nap') {
    spriteId = 'nap'               // 等太久：躺下睡
  } else {
    if (state !== fishStateKey) {
      fishStateKey = state
      fishClipUntil = 0
    }
    const now = Date.now()
    if (!fishClipId || now >= fishClipUntil) {
      const pool = FISH_POOLS[state] || FISH_POOLS.idle
      const options = pool.filter((entry) => FISH_SPRITES[entry.id])
      const fresh = options.filter((entry) => entry.id !== fishClipId)
      const use = fresh.length > 0 ? fresh : options
      const total = use.reduce((sum, entry) => sum + (entry.weight || 1), 0)
      let roll = Math.random() * total
      let pick = use[0]
      for (const entry of use) {
        roll -= entry.weight || 1
        if (roll <= 0) { pick = entry; break }
      }
      fishClipId = pick.id
      const spec = FISH_SPRITES[pick.id]
      fishClipUntil = now + (pick.loops || 1) * (spec.frameCount / spec.fps) * 1000
    }
    spriteId = fishClipId
  }
  paintFishArt(spriteId)
  if (el.fishBubble && !el.fishBubble.hidden) el.fishBubble.textContent = fishBubbleText()
}
function fishSay(toggle) {
  if (!el.fishBubble || !el.fishFab || el.fishFab.hidden) return
  el.fishBubble.textContent = fishBubbleText()
  if (toggle && !el.fishBubble.hidden) {
    el.fishBubble.hidden = true
    return
  }
  el.fishBubble.hidden = false
  clearTimeout(fishBubbleTimer)
  fishBubbleTimer = setTimeout(() => { if (el.fishBubble) el.fishBubble.hidden = true }, 2600)
}

function initFish() {
  const fab = el.fishFab
  const body = el.fishBody
  if (!fab || !body) return
  loadFishArt()
  const saved = readFishPos()
  const w = document.documentElement.clientWidth || window.innerWidth || 360
  const h = window.innerHeight || document.documentElement.clientHeight || 640
  if (saved) placeFish(saved.x, saved.y, false)
  else placeFish(w - FISH_SIZE - 16, h - FISH_SIZE - 96, false)
  window.addEventListener('resize', () => {
    const cur = readFishPos()
    if (cur) placeFish(cur.x, cur.y, false)
  })

  const down = (ev) => {
    if (typeof ev.button === 'number' && ev.button !== 0) return
    fishDrag = {
      x: ev.clientX, y: ev.clientY,
      left: parseFloat(fab.style.left) || 0,
      top: parseFloat(fab.style.top) || 0,
      moved: false,
    }
    fab.classList.add('drag')
    try { body.setPointerCapture(ev.pointerId) } catch (_) {}
  }
  const move = (ev) => {
    if (!fishDrag) return
    const dx = ev.clientX - fishDrag.x
    const dy = ev.clientY - fishDrag.y
    if (!fishDrag.moved && Math.abs(dx) + Math.abs(dy) > FISH_TAP_SLOP) fishDrag.moved = true
    if (fishDrag.moved) placeFish(fishDrag.left + dx, fishDrag.top + dy, false)
  }
  const up = (ev) => {
    if (!fishDrag) return
    const moved = fishDrag.moved
    fishDrag = null
    fab.classList.remove('drag')
    try { body.releasePointerCapture(ev.pointerId) } catch (_) {}
    if (moved) {
      placeFish(parseFloat(fab.style.left) || 0, parseFloat(fab.style.top) || 0, true)
      return
    }
    S.fishPokeUntil = Date.now() + 1800
    fishSync()
    fishSay(true)
  }
  body.addEventListener('pointerdown', down)
  body.addEventListener('pointermove', move)
  body.addEventListener('pointerup', up)
  body.addEventListener('pointercancel', () => { fishDrag = null; fab.classList.remove('drag') })
  fab.hidden = true
  fishSync()
  setInterval(() => {
    if (!S.paired || S.view !== 'chat' || !S.current) return
    const id = nextCmdIdFor('live_state')
    S.liveCmd = id
    sendSealed({ t: 'cmd.list_sessions', cmdId: id })
  }, 5000)
  // 每 400ms 重算一次：动作播完换下一个、talk/done 窗口过期后自动回落
  setInterval(() => {
    if (!S.paired || S.view === 'pair' || !el.fishFab || el.fishFab.hidden) return
    fishSync()
  }, 400)
}

function boot() {
  initEls()
  initFish()
  // 日志栏偏好：记住上次是收起还是展开（默认收起）
  S.logOpen = localStorage.getItem('drc.logOpen') === '1'
  el.logCard.hidden = !S.logOpen
  if (el.logToggleBtn) el.logToggleBtn.textContent = S.logOpen ? '📜 收起日志' : '📜 日志'

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
  el.refreshBtn?.addEventListener('click', () => { void refreshSessions() })
  el.updateBtn?.addEventListener('click', () => {
    closeMenu()
    try { window.dshApp.checkUpdate() } catch (_) { log('「更新」只在 App 内可用') }
  })
  el.backBtn?.addEventListener('click', goBack)
  el.sendBtn?.addEventListener('click', cmdSendPrompt)
  el.earlierBtn?.addEventListener('click', loadEarlier)
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
    S.modelErr = ''
    sendSealed({ t: 'cmd.get_models', cmdId: nextCmdIdFor('models') })
    renderModelSheet()
  })
  el.clearLog?.addEventListener('click', () => { logLines.length = 0; if (el.log) el.log.textContent = '' })

  // 日志栏：点「日志」展开，再点「收起」缩回；选择会被记住
  el.logToggleBtn?.addEventListener('click', () => {
    closeMenu()
    S.logOpen = !S.logOpen
    localStorage.setItem('drc.logOpen', S.logOpen ? '1' : '0')
    el.logCard.hidden = !S.logOpen
    el.logToggleBtn.textContent = S.logOpen ? '📜 收起日志' : '📜 日志'
  })

  el.reconnectBtn?.addEventListener('click', () => {
    S.reconnectTries = 0
    stopReconnect()
    connect()
  })

  // 小齿轮菜单：更新 / 日志 / 重新配对 都收进来，顶部就清爽了
  el.gearBtn?.addEventListener('click', (e) => { e.stopPropagation(); toggleMenu() })
  el.menuClose?.addEventListener('click', closeMenu)
  el.menuWrap?.addEventListener('click', (e) => { if (e.target === el.menuWrap) closeMenu() })
  el.cfCancel?.addEventListener('click', closeRepairConfirm)
  el.cfOk?.addEventListener('click', () => {
    if (el.cfOk.disabled) return
    closeRepairConfirm()
    doRepairPair()
  })
  el.confirmWrap?.addEventListener('click', (e) => { if (e.target === el.confirmWrap) closeRepairConfirm() })

  // 重新配对：点菜单项先弹确认（还要等 5 秒），确认后才断
  el.repairBtn?.addEventListener('click', () => { closeMenu(); openRepairConfirm() })

  // 回到前台立刻重连，不等退避；切后台时靠前台服务+心跳尽量撑住。
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) return
    if (!(S.ws && S.ws.readyState === 1)) {
      if (loadSession()) {
        S.reconnectTries = 0
        stopReconnect()
        connect()
      }
      return
    }
    // 已经连着但可能已经"半死"（Android 后台最常见的形态）：回前台先确认链路，
    // 顺便把列表重拉一次 —— 用户从后台切回来最想看到的就是最新状态。
    // 链路被判死时它已经在重连了，这时不要再去撞一次（会多报一条"连接断了"）。
    if (checkLinkAlive()) void refreshSessions({ silent: true })
  })

  setStatus('未连接')
  syncStopBtn()
  log('客户端已加载，中继: ' + S.relay)

  // 链路看门狗（坑在「半开连接」）：Android WebView 退到后台后，socket 常常既没
  // 触发 onclose、readyState 也还是 1，但对面已经不回任何东西 —— 那时所有命令都
  // 发得出去、收不到回执，用户看到的就是"按了没反应、只能退出重进"。心跳 25 秒
  // 一次、pong 走同一根线，所以 75 秒没有任何入帧就判死、主动重连。
  setInterval(() => { checkLinkAlive() }, 15000)

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

// 调试/自测挂钩：无头浏览器里可以直接灌事件、检查 DOM（不影响正常使用）
try {
  globalThis.__drc = { S, el, applyEvent, handleFrame, renderSessions, renderModelSheet, showView, openSession, goBack, effectiveModel, modelBadgeText, cmdNewSession, findEmptySession, loadImage, findImagePaths, renderMessages, fishSync, fishSay, fishState, FISH_POOLS, fishFrameAt, fishSpriteOffset, FISH_SPRITES, historyCmd, loadEarlier, HISTORY_PAGE_LIMIT, readCache, saveCache, updateRunBanner, syncStopBtn, refreshSessions, fmtAgo, fmtElapsed, runProgressText, checkLinkAlive }
} catch (_) {}

