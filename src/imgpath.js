/**
 * 从一段正文里挑出「主机上的图片文件路径」。
 *
 * 背景（2026-11-02 用户需求）：DSH 在主机上干活时会产出静态效果图（Unity VFX 预览之类），
 * 它在正文里告诉用户一个路径。手机上没地方打开它，于是这个模块负责把那些路径认出来，
 * 交给 client.js 变成一颗「点我看图」的按钮。
 *
 * 认法有两路，因为模型写路径的姿势不止一种：
 *   1. 裸路径：`E:\Proj\Preview.png`、`file:///E:/Proj/Preview.png`
 *   2. 被引号/反引号包起来的路径（这种最常见，而且能带空格）：
 *      `` `E:\My Project\特效.png` ``、"E:\a\b.png"
 *
 * 刻意不做的事：**不校验文件是否真的存在**（手机上没这个能力），也不猜相对路径
 * （主机侧只接受绝对路径，猜出来的东西只会得到一句"请给绝对路径"）。
 */

// 扩展名白名单必须与主机侧 `src/core/file-image.ts` 的 IMAGE_MIME 一致：
// 两边不一致的表现是"按钮出现了、点了报扩展名不支持"。
const EXT = '(?:png|jpe?g|webp|gif|bmp)'

// 裸路径：盘符 + 冒号 + 分隔符 + 不含空白/引号/反引号/尖括号的连续片段
const BARE_RE = new RegExp('(?:file:///)?[A-Za-z]:[\\\\/][^\\s"\'`<>|?*\\r\\n]*?\\.' + EXT + '(?![A-Za-z0-9])', 'gi')

// 引号里带空格的路径
const QUOTED_RE = new RegExp('[`"\']([^`"\']*?[\\\\/][^`"\']*?\\.' + EXT + ')[`"\']', 'gi')

// 句末标点不算路径的一部分（中文正文里 `E:\a.png。` 很常见）
const TRAIL_RE = /[.,;:!?，。；：！？、）)】》」』"'“”]+$/

function normalize(raw) {
  let p = String(raw || '').trim()
  if (p === '') return ''
  if (/^file:\/\//i.test(p)) {
    p = p.replace(/^file:\/\/*/i, '')
    try {
      p = decodeURIComponent(p)
    } catch (_) {
      // 解不开就原样用：总比丢掉好
    }
  }
  p = p.replace(TRAIL_RE, '')
  return p
}

/**
 * @param {string} text 正文
 * @param {number} [max] 最多返回几条（默认 6：一条消息里堆十张图没人看）
 * @returns {string[]} 去重后的绝对路径
 */
export function findImagePaths(text, max = 6) {
  if (typeof text !== 'string' || text.length === 0) return []
  const out = []
  const seen = new Set()
  const push = (raw) => {
    const p = normalize(raw)
    // 太短的（例如 `E:\a.png` 也算合法，只有 8 个字符）只挡明显垃圾
    if (p.length < 4) return
    const key = p.toLowerCase()
    if (seen.has(key)) return
    seen.add(key)
    out.push(p)
  }

  // 先收引号里的：它们更完整（能带空格），而且通常是模型真的想让人打开的那个
  QUOTED_RE.lastIndex = 0
  let m
  while ((m = QUOTED_RE.exec(text)) !== null) {
    push(m[1])
    if (out.length >= max) return out
  }

  BARE_RE.lastIndex = 0
  while ((m = BARE_RE.exec(text)) !== null) {
    push(m[0])
    if (out.length >= max) break
  }
  return out
}
