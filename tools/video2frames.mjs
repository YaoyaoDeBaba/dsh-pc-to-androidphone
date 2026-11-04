#!/usr/bin/env node
// 视频 → 透明序列帧 / 雪碧图 生成器
//
//   node tools/video2frames.mjs idle.mp4 --name idle
//   node tools/video2frames.mjs talk.mp4 --name talk --fps 12 --height 340 --key 0x00FF00
//
// 做的事：
//   1) ffmpeg 抽帧 + 抠掉纯色背景（chromakey）+ 去绿边（despill）
//   2) 自动算非透明内容的包围盒（alphaextract + cropdetect），所有帧统一裁切，
//      这样同一角色的多段动画不会互相错位
//   3) 按目标高度缩放
//   4) 拼成一张横向/网格雪碧图 + 写 manifest.json（渲染端只读 manifest）
//   5) 打印体积，超过预算会警告
//
// 只依赖 ffmpeg / ffprobe，不需要 npm 依赖。

import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'

const argv = process.argv.slice(2)
if (!argv.length || argv.includes('-h') || argv.includes('--help')) {
  console.log(`用法: node tools/video2frames.mjs <input.mp4> [选项]

  --name <名字>     动画名（决定输出文件名，如 idle / talk / think）默认取输入文件名
  --out <目录>      输出目录，默认 app/src/main/assets/pet
  --fps <数字>      抽帧帧率，默认 12（手机端够用，帧数少体积小）
  --height <像素>   角色目标高度，默认 340
  --key <颜色>      背景色，默认 0x00FF00（纯绿）；用纯洋红就写 0xFF00FF
  --cols <数字>     雪碧图列数，默认自动（最多 8 列）
  --tolerance <数>  抠图容差 0~1，默认 0.18，边缘残色就调大
  --keep            保留中间产物（抠好的逐帧 PNG）
  --dry             只打印会做什么，不真跑

素材要求见 README「虚拟形象素材规格」。`)
  process.exit(0)
}

function opt(name, def) {
  const i = argv.indexOf('--' + name)
  return i >= 0 && argv[i + 1] && !argv[i + 1].startsWith('--') ? argv[i + 1] : def
}
const flag = (n) => argv.includes('--' + n)

const input = argv.find((a) => !a.startsWith('--') && /\.(mp4|mov|webm|mkv|gif|webp)$/i.test(a))
if (!input) {
  console.error('没找到输入视频文件')
  process.exit(1)
}
if (!fs.existsSync(input)) {
  console.error('文件不存在：' + input)
  process.exit(1)
}

const name = opt('name', path.basename(input).replace(/\.[^.]+$/, ''))
const outDir = path.resolve(opt('out', 'app/src/main/assets/pet'))
const fps = Number(opt('fps', 12))
const targetH = Number(opt('height', 340))
const keyColor = opt('key', '0x00FF00')
const tolerance = Number(opt('tolerance', 0.18))
const keep = flag('keep')
const dry = flag('dry')

const BUDGET_PER_CLIP = 1.6 * 1024 * 1024   // 单段动画建议上限
const BUDGET_TOTAL = 8 * 1024 * 1024        // 全部素材建议上限

function run(bin, args) {
  const r = spawnSync(bin, args, { encoding: 'utf8', maxBuffer: 128 * 1024 * 1024 })
  return (r.stdout || '') + (r.stderr || '')
}
// ffmpeg 的诊断（cropdetect 的 crop=xxxx）都走 stderr，所以这里把两路合起来
function tryRun(bin, args) {
  const r = spawnSync(bin, args, { encoding: 'utf8', maxBuffer: 128 * 1024 * 1024 })
  if (r.error) return { ok: false, out: String(r.error.message || r.error) }
  return { ok: r.status === 0, out: (r.stdout || '') + (r.stderr || '') }
}

// ---- 1. 探测源视频 ----
const probe = tryRun('ffprobe', ['-v', 'error', '-select_streams', 'v:0',
  '-show_entries', 'stream=width,height,r_frame_rate,nb_frames,duration',
  '-of', 'default=noprint_wrappers=1', input])
if (!probe.ok) {
  console.error('ffprobe 失败（ffmpeg 装了但 ffprobe 不在 PATH？）')
  console.error(probe.out.slice(0, 500))
  process.exit(1)
}
const meta = Object.fromEntries(
  probe.out.split('\n').map((l) => l.trim()).filter(Boolean).map((l) => {
    const i = l.indexOf('=')
    return [l.slice(0, i), l.slice(i + 1)]
  }),
)
const srcW = Number(meta.width || 0)
const srcH = Number(meta.height || 0)
const srcFps = meta.r_frame_rate ? (() => {
  const [a, b] = meta.r_frame_rate.split('/').map(Number)
  return b ? a / b : a
})() : 0
const srcDur = Number(meta.duration || 0)
const estFrames = srcDur && fps ? Math.max(1, Math.round(srcDur * fps)) : Number(meta.nb_frames || 0)

console.log(`源视频: ${path.basename(input)}  ${srcW}x${srcH}  ${srcFps.toFixed(2)}fps  ${srcDur.toFixed(2)}s`)
console.log(`计划: ${name}  抽 ${fps}fps ≈ ${estFrames} 帧  高 ${targetH}px  背景 ${keyColor}`)
if (dry) process.exit(0)

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'v2f-'))
const rawDir = path.join(tmp, 'raw')
const cropDir = path.join(tmp, 'crop')
fs.mkdirSync(rawDir, { recursive: true })
fs.mkdirSync(cropDir, { recursive: true })
fs.mkdirSync(outDir, { recursive: true })

// ---- 2. 抽帧 + 抠背景 ----
// tolerance 映射到 chromakey 的 similarity/blend：0.18 → similarity 0.18 blend 0.08
const sim = Math.min(0.95, Math.max(0.01, tolerance))
const blend = Math.min(0.5, sim * 0.45)
const keyChain = [
  `fps=${fps}`,
  `chromakey=${keyColor}:${sim.toFixed(3)}:${blend.toFixed(3)}`,
  'despill=type=green:mix=0.6:expand=0.3',
  'format=rgba',
].join(',')

const extract = tryRun('ffmpeg', ['-y', '-v', 'error', '-i', input, '-vf', keyChain,
  path.join(rawDir, 'f%04d.png')])
if (!extract.ok) {
  console.error('抽帧失败：')
  console.error(extract.out.slice(0, 800))
  process.exit(1)
}
const rawFrames = fs.readdirSync(rawDir).filter((f) => f.endsWith('.png')).sort()
if (!rawFrames.length) {
  console.error('没抽到帧，检查输入文件')
  process.exit(1)
}
console.log(`抽帧完成: ${rawFrames.length} 帧`)

// ---- 3. 自动算包围盒（alphaextract 把透明通道变成灰度，再用 cropdetect 量内容框；
//        逐帧量完取并集，这样角色摆动/伸手的幅度也算进去） ----
function detectCropSequence(dir) {
  const r = tryRun('ffmpeg', ['-hide_banner', '-i', path.join(dir, 'f%04d.png'),
    '-vf', 'alphaextract,cropdetect=limit=0.02:round=2:reset=0', '-f', 'null', '-'])
  const hits = [...r.out.matchAll(/crop=(\d+):(\d+):(\d+):(\d+)/g)]
  if (!hits.length) return null
  let box = null
  for (const m of hits) {
    const c = { w: Number(m[1]), h: Number(m[2]), x: Number(m[3]), y: Number(m[4]) }
    if (!box) box = { ...c }
    else {
      const x1 = Math.min(box.x, c.x), y1 = Math.min(box.y, c.y)
      const x2 = Math.max(box.x + box.w, c.x + c.w), y2 = Math.max(box.y + box.h, c.y + c.h)
      box = { x: x1, y: y1, w: x2 - x1, h: y2 - y1 }
    }
  }
  return box
}
let box = detectCropSequence(rawDir)
if (!box || box.w < 8 || box.h < 8) {
  box = { x: 0, y: 0, w: srcW, h: srcH }
  console.log('⚠️  自动裁切没测出来（背景不纯？容差太小？），退回整帧')
} else {
  // 留 2% 余量，避免动画边缘被切掉
  const padX = Math.round(box.w * 0.02), padY = Math.round(box.h * 0.02)
  box = {
    x: Math.max(0, box.x - padX), y: Math.max(0, box.y - padY),
    w: Math.min(srcW - Math.max(0, box.x - padX), box.w + padX * 2),
    h: Math.min(srcH - Math.max(0, box.y - padY), box.h + padY * 2),
  }
}
console.log(`裁切框: ${box.w}x${box.h} @ ${box.x},${box.y}`)

// ---- 4. 统一裁切 + 缩放 ----
const cropChain = `crop=${box.w}:${box.h}:${box.x}:${box.y},scale=-2:${targetH}:flags=lanczos`
const crop = tryRun('ffmpeg', ['-y', '-v', 'error', '-i', path.join(rawDir, 'f%04d.png'),
  '-vf', cropChain, path.join(cropDir, 'c%04d.png')])
if (!crop.ok) {
  console.error('裁切缩放失败：')
  console.error(crop.out.slice(0, 800))
  process.exit(1)
}
const frames = fs.readdirSync(cropDir).filter((f) => f.endsWith('.png')).sort()
// 取实际帧尺寸（缩放后宽度可能因 -2 对齐变化）
const dimProbe = tryRun('ffprobe', ['-v', 'error', '-select_streams', 'v:0',
  '-show_entries', 'stream=width,height', '-of', 'csv=p=0', path.join(cropDir, frames[0])])
const [frameW, frameH] = dimProbe.out.trim().split(',').map(Number)

// ---- 5. 拼雪碧图 ----
const cols = Math.max(1, Number(opt('cols', Math.min(8, frames.length))))
const rows = Math.ceil(frames.length / cols)
const sheetName = `${name}.png`
const sheetPath = path.join(outDir, sheetName)
const tile = tryRun('ffmpeg', ['-y', '-v', 'error', '-i', path.join(cropDir, 'c%04d.png'),
  '-vf', `tile=${cols}x${rows}:padding=0:margin=0:color=#00000000`,
  '-frames:v', '1', sheetPath])
if (!tile.ok) {
  console.error('拼图失败：')
  console.error(tile.out.slice(0, 800))
  process.exit(1)
}

// ---- 6. 写 manifest + 汇报 ----
const manifest = {
  name,
  sheet: sheetName,
  cols, rows,
  frames: frames.length,
  frameW, frameH,
  fps,
  loop: true,
  generatedFrom: path.basename(input),
  generatedAt: new Date().toISOString(),
}
const manifestPath = path.join(outDir, `${name}.json`)
fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2))

const totalBytes = fs.readdirSync(outDir)
  .filter((f) => f.endsWith('.png') || f.endsWith('.json'))
  .reduce((n, f) => n + fs.statSync(path.join(outDir, f)).size, 0)
const sheetBytes = fs.statSync(sheetPath).size
const kb = (n) => (n / 1024).toFixed(1) + ' KB'

console.log(`雪碧图: ${sheetName}  ${cols}x${rows} 格  每帧 ${frameW}x${frameH}  ${kb(sheetBytes)}`)
console.log(`清单: ${name}.json`)
console.log(`该动画总计: ${kb(totalBytes)}`)
if (sheetBytes > BUDGET_PER_CLIP) {
  console.log(`⚠️  单段超过 ${kb(BUDGET_PER_CLIP)}：把 --fps 降到 8~10 或 --height 降到 280 再试`)
}
if (totalBytes > BUDGET_TOTAL) {
  console.log(`⚠️  全部素材超过 ${kb(BUDGET_TOTAL)}，手机端建议压一压`)
}

if (keep) console.log(`中间产物保留在: ${tmp}`)
else fs.rmSync(tmp, { recursive: true, force: true })
