#!/usr/bin/env node
/**
 * 给电脑端的 @dsh-remote/plugin 打本地补丁：暴露三个新命令，手机端才能
 *   - 改会话名称        cmd.rename_session
 *   - 拿模型清单        cmd.get_models
 *   - 切模型+努力程度   cmd.set_model
 *
 * 官方插件（0.5.1 / 0.5.3）协议里没有这三条，但 DSH 内核本身支持：
 *   sessionController.commands.rename({sessionId,title})
 *   sessionController.modelCatalog()
 *   sessionController.commands.selectModel({sessionId,provider,model,reasoningEffort})
 *
 * 用法：
 *   node tools/patch-plugin.mjs            # 打补丁（已打过就跳过）
 *   node tools/patch-plugin.mjs --check    # 只检查状态，不写文件
 *   node tools/patch-plugin.mjs --restore  # 用备份还原
 *
 * 注意：补丁写在 node_modules 里，插件升级后会被覆盖 —— 升级后重跑一次即可。
 * 打完必须重启 DSH 才生效（插件在启动时加载）。
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'

const MARK = '// [dsh-remote-plus]'
const HOME = process.env.DSH_HOME || path.join(os.homedir(), '.dsh')
const CANDIDATES = [
  path.join(HOME, 'profiles', 'desktop', 'node_modules', '@dsh-remote', 'plugin', 'dist', 'bundle', 'index.js'),
  path.join(HOME, 'profiles', 'web', 'node_modules', '@dsh-remote', 'plugin', 'dist', 'bundle', 'index.js'),
]

const args = new Set(process.argv.slice(2))
const checkOnly = args.has('--check')
const restore = args.has('--restore')
const statusOnly = args.has('--status')

function findPlugin() {
  for (const p of CANDIDATES) if (fs.existsSync(p)) return p
  return null
}

const target = findPlugin()
if (!target) {
  console.error('找不到 @dsh-remote/plugin 的 bundle。请确认 DSH_HOME（当前：' + HOME + '）')
  process.exit(1)
}

const bak = target + '.dsh-remote-plus.bak'
console.log('插件：' + target)

if (restore) {
  if (!fs.existsSync(bak)) {
    console.error('没有备份可还原：' + bak)
    process.exit(1)
  }
  fs.copyFileSync(bak, target)
  console.log('已用备份还原。重启 DSH 生效。')
  process.exit(0)
}

let src = fs.readFileSync(target, 'utf8')
const already = src.includes(MARK)

if (checkOnly) {
  console.log(already ? '状态：已打过补丁' : '状态：未打补丁')
  process.exit(0)
}

// --status：补丁在不在 + 当前 DSH 进程是不是打完补丁之后才启动的
if (statusOnly) {
  const execSync = (await import('node:child_process')).execSync
  console.log('补丁：' + (already ? '已打' : '未打'))
  const statusFile = path.join(HOME, 'dsh-remote-control', 'status.json')
  let pid = 0
  try {
    pid = JSON.parse(fs.readFileSync(statusFile, 'utf8')).pid || 0
  } catch {
    console.log('状态：读不到 ' + statusFile + '（远控插件可能没跑）')
    process.exit(already ? 0 : 2)
  }
  const patchedAt = fs.statSync(target).mtime
  let started = null
  try {
    const iso = execSync(
      `powershell -NoProfile -Command "(Get-Process -Id ${pid} -ErrorAction Stop).StartTime.ToUniversalTime().ToString('o')"`,
      { encoding: 'utf8' },
    ).trim()
    started = new Date(iso)
  } catch {
    console.log(`进程：pid ${pid}（查不到启动时间）`)
  }
  if (started) {
    const fresh = started > patchedAt
    console.log(`补丁写入：${patchedAt.toISOString()}`)
    console.log(`当前 DSH：pid ${pid}，启动于 ${started.toISOString()}`)
    console.log(fresh ? '结论：进程是打完补丁之后启动的 → 补丁已生效' : '结论：进程比补丁旧 → 重启 DSH 才生效')
    process.exit(fresh && already ? 0 : 3)
  }
  process.exit(already ? 0 : 2)
}
if (already) {
  console.log('已打过补丁，跳过（要重打请先 --restore）')
  process.exit(0)
}

// ---------- 补丁片段 ----------

const SCHEMAS = `${MARK} 手机端：改名 / 模型清单 / 切模型（本地补丁，插件升级后重跑 tools/patch-plugin.mjs）
var cmdRenameSession = external_exports.object({
  t: external_exports.literal("cmd.rename_session"),
  cmdId: nonEmpty2,
  sessionId: nonEmpty2,
  title: external_exports.string().min(1).max(200)
});
var cmdGetModels = external_exports.object({
  t: external_exports.literal("cmd.get_models"),
  cmdId: nonEmpty2
});
var cmdSetModel = external_exports.object({
  t: external_exports.literal("cmd.set_model"),
  cmdId: nonEmpty2,
  sessionId: nonEmpty2,
  provider: nonEmpty2,
  model: nonEmpty2,
  reasoningEffort: external_exports.string().optional()
});
`

const KERNEL_FUNCS = `  ${MARK} 手机端：改名 / 模型清单 / 切模型（含努力程度）
  async function renameSession(sessionId, title) {
    const commands = services.sessionController?.commands;
    const rename = fn(commands, "rename");
    if (!rename) return { ok: false, message: \`这一代内核的 sessionController.commands 上没有 rename()（成员：\${shapeOf(commands)}）\` };
    try {
      const out = await rename.call(commands, { sessionId, title });
      return { ok: true, title: typeof out?.title === "string" && out.title !== "" ? out.title : title };
    } catch (error63) {
      return { ok: false, message: messageOf(error63) };
    }
  }
  async function modelCatalog() {
    const controller = services.sessionController;
    const read = fn(controller, "modelCatalog");
    if (!read) return { ok: false, message: \`这一代内核的 sessionController 上没有 modelCatalog()（成员：\${shapeOf(controller)}）\` };
    try {
      const catalog = await read.call(controller);
      const groups = Array.isArray(catalog?.groups) ? catalog.groups : [];
      return {
        ok: true,
        catalog: {
          default: catalog?.default ?? null,
          groups: groups.map((group) => ({
            id: String(group?.id ?? ""),
            name: String(group?.name ?? group?.id ?? ""),
            models: (Array.isArray(group?.models) ? group.models : []).map((model) => ({
              id: String(model?.id ?? ""),
              name: String(model?.name ?? model?.id ?? ""),
              ...(Array.isArray(model?.reasoning?.efforts) && model.reasoning.efforts.length > 0
                ? { efforts: model.reasoning.efforts.map((effort) => ({ id: String(effort?.id ?? ""), name: String(effort?.name ?? effort?.id ?? "") })) }
                : {}),
              ...(typeof model?.reasoning?.defaultEffort === "string" ? { defaultEffort: model.reasoning.defaultEffort } : {})
            }))
          }))
        },
        failures: (Array.isArray(catalog?.failures) ? catalog.failures : []).map((failure) => ({
          id: String(failure?.id ?? ""),
          message: String(failure?.message ?? "")
        }))
      };
    } catch (error63) {
      return { ok: false, message: messageOf(error63) };
    }
  }
  async function selectModel(sessionId, provider, model, reasoningEffort) {
    const commands = services.sessionController?.commands;
    const select = fn(commands, "selectModel");
    if (!select) return { ok: false, message: \`这一代内核的 sessionController.commands 上没有 selectModel()（成员：\${shapeOf(commands)}）\` };
    try {
      const requested = { sessionId, provider, model };
      if (typeof reasoningEffort === "string" && reasoningEffort !== "") requested.reasoningEffort = reasoningEffort;
      const out = await select.call(commands, requested);
      const selected = out && typeof out.selected === "object" && out.selected !== null ? out.selected : requested;
      return { ok: true, selected };
    } catch (error63) {
      return { ok: false, message: messageOf(error63) };
    }
  }
`

const DISPATCH = `        ${MARK} 手机端改名 / 模型清单 / 切模型
        case "cmd.rename_session": {
          const outcome = await this.kernel.renameSession(cmd.sessionId, cmd.title);
          if (!outcome.ok) {
            reply(false, { message: outcome.message ?? "改名失败" });
            return;
          }
          reply(true, { data: { kind: "title", sessionId: cmd.sessionId, title: outcome.title } });
          await this.pushSessions("renamed").catch(() => {
          });
          return;
        }
        case "cmd.get_models": {
          const outcome = await this.kernel.modelCatalog();
          if (!outcome.ok) {
            reply(false, { message: outcome.message ?? "拿不到模型清单" });
            return;
          }
          reply(true, { data: { kind: "catalog", catalog: outcome.catalog, failures: outcome.failures ?? [] } });
          return;
        }
        case "cmd.set_model": {
          const outcome = await this.kernel.selectModel(cmd.sessionId, cmd.provider, cmd.model, cmd.reasoningEffort);
          if (!outcome.ok) {
            reply(false, { message: outcome.message ?? "切换模型失败" });
            return;
          }
          reply(true, { data: { kind: "model", sessionId: cmd.sessionId, selected: outcome.selected } });
          return;
        }
`

// ---------- 替换（每处都必须命中，命中数不对就整体放弃） ----------

let applied = []
function patchOnce(label, from, to) {
  const count = src.split(from).length - 1
  if (count !== 1) {
    console.error(`✗ 锚点「${label}」命中 ${count} 次（应为 1），插件版本可能变了，放弃打补丁`)
    process.exit(2)
  }
  src = src.replace(from, to)
  applied.push(label)
}

// 1) 新增三个命令的 schema（放在 cmdPayload 联合前面）
patchOnce('schemas',
  'var cmdPayload = external_exports.discriminatedUnion("t", [',
  SCHEMAS + 'var cmdPayload = external_exports.discriminatedUnion("t", [')

// 2) 加进 discriminatedUnion
patchOnce('union',
  '  cmdGetPending,\n  cmdArchiveSession\n]);',
  '  cmdGetPending,\n  cmdArchiveSession,\n  cmdRenameSession,\n  cmdGetModels,\n  cmdSetModel\n]);')

// 3) 类型表
patchOnce('payload-types',
  '  cmdArchiveSession: "cmd.archive_session",',
  '  cmdArchiveSession: "cmd.archive_session",\n  cmdRenameSession: "cmd.rename_session",\n  cmdGetModels: "cmd.get_models",\n  cmdSetModel: "cmd.set_model",')

patchOnce('cmd-types',
  '  PAYLOAD_TYPES.cmdArchiveSession\n];',
  '  PAYLOAD_TYPES.cmdArchiveSession,\n  PAYLOAD_TYPES.cmdRenameSession,\n  PAYLOAD_TYPES.cmdGetModels,\n  PAYLOAD_TYPES.cmdSetModel\n];')

// 4) 内核侧函数实现（插在 kernel 对象 return 之前）
patchOnce('kernel-funcs',
  '  return {\n    carrier: "services",\n    listSessions,',
  KERNEL_FUNCS + '  return {\n    carrier: "services",\n    listSessions,')

// 5) kernel 对象上挂出去
patchOnce('kernel-keys',
  '    archiveSession,\n',
  '    archiveSession,\n    renameSession,\n    modelCatalog,\n    selectModel,\n')

// 6) 命令分发
patchOnce('dispatch',
  '          reply(true, { data: { archived } });\n          await this.pushSessions("archived");\n          return;\n        }\n',
  '          reply(true, { data: { archived } });\n          await this.pushSessions("archived");\n          return;\n        }\n' + DISPATCH)

// ---------- 落盘 ----------
if (!fs.existsSync(bak)) fs.copyFileSync(target, bak)
fs.writeFileSync(target, src)
console.log('✓ 已打补丁：' + applied.join(', '))
console.log('✓ 备份：' + bak)
console.log('→ 重启 DSH 后生效（退出应用再打开；会话历史不会丢）')
