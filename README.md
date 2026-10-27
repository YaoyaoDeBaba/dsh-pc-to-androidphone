# 大肥鱼远控 (DSH Remote for Android)

在手机上远程指挥家里电脑上的 DSH（大肥鱼），出差也能用。

## 这是什么

- 一个极薄的 **Android WebView 外壳**（`MainActivity.java`）
- 里面装的是网页版客户端（`app/src/main/assets/index.html` + `app.js`）
- 客户端通过官方协议连中继 `wss://drc.provid.cc`，端到端加密
- 用 **GitHub Actions 云端编译**，本地不需要装 Android Studio

## 怎么出 APK

1. 把整个项目上传到这个仓库
2. 打开仓库的 **Actions** 标签页
3. 等 `Build APK` 跑完（约 3-8 分钟）
4. 点进这次运行 → 底部 **Artifacts** → 下载 `dsh-remote-debug`
5. 解压得到 `app-debug.apk` → 传到手机 → 安装

## 结构

```
.github/workflows/build.yml   # 云端编译
app/src/main/java/.../MainActivity.java  # WebView 外壳
app/src/main/assets/index.html            # 客户端界面
app/src/main/assets/app.js                # 客户端逻辑（协议 + 加密）
tools/patch-plugin.mjs                    # 电脑端插件补丁（改名 / 模型清单 / 切模型）
```

## 电脑端插件补丁（改名、选模型、努力程度）

官方的 `@dsh-remote/plugin`（0.5.1 / 0.5.3）协议里只有 10 条命令，**没有**改名、模型清单、切模型。
这三项的底层能力 DSH 内核是有的，所以这里给插件打一个本地小补丁，补出三条命令：

| 命令 | 作用 | 走的电脑端接口 |
|---|---|---|
| `cmd.rename_session` | 改会话名称 | `sessionController.commands.rename` |
| `cmd.get_models` | 拿模型清单 + 每档努力程度 | `sessionController.modelCatalog()` |
| `cmd.set_model` | 切模型 / 调努力程度 | `sessionController.commands.selectModel` |

用法（在电脑上、仓库根目录）：

```bash
node tools/patch-plugin.mjs --check     # 看有没有打过
node tools/patch-plugin.mjs             # 打补丁（已打过会跳过）
node tools/patch-plugin.mjs --restore   # 还原备份
```

注意：

- 补丁写在 `~/.dsh/profiles/desktop/node_modules/@dsh-remote/plugin` 里，**打完要重启 DSH 才生效**（会话历史不会丢）
- **插件升级会覆盖补丁** → 升级后重跑一次 `node tools/patch-plugin.mjs` 即可
- 第一次打补丁会在旁边留一份 `index.js.dsh-remote-plus.bak` 备份

## 手机端界面自测（不用手机）

改完界面先在本机跑一遍，省得装到手机上才发现问题：

```bash
npm run build
pwsh -File tools/run-ui-test.ps1
```

它用无头 Edge/Chrome 打开 `tools/ui-test.html`，把「模型清单回执 / 改名回执 /
新建会话回执 / ev.model 广播 / 失败回执」这些协议帧直接灌进 `app.js`，
再检查 DOM 有没有按预期变化（当前 21 项）。
