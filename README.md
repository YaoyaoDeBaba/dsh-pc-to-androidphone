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
```
