package com.dsh.remote;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * 自更新：查最新 Release -> 版本更高就问用户 -> 自己用 HTTP 下载 -> 拉起安装器。
 *
 * 为什么不用系统 DownloadManager：小米 MIUI 把系统下载引擎换成了「迅雷下载」，
 * 请求进去后经常 0 速度卡死、既不完成也不失败，App 根本收不到结果。
 * 这里改成自己下载：超时/0 字节判死、自动重试 4 次、失败直接开浏览器下 APK 兜底。
 * 下载全程用弹窗 + 页面日志栏实时反馈，不再“静默失败”。
 * 安装走自家 ApkProvider 的 content:// URI，保持零第三方依赖。
 */
public final class UpdateManager {

    private static final String OWNER = "YaoyaoDeBaba";
    private static final String REPO = "dsh-pc-to-androidphone";
    private static final String API =
            "https://api.github.com/repos/" + OWNER + "/" + REPO + "/releases/latest";

    /** 下载失败自动重试次数上限（每次间隔 3 秒）。 */
    private static final int MAX_DOWNLOAD_ATTEMPTS = 4;
    /** 连接超时 / 单次读超时：15 秒没动静就算卡死，换下一次尝试。 */
    private static final int CONNECT_TIMEOUT = 10000;
    private static final int READ_TIMEOUT = 15000;

    /** 防止连点「下载更新」导致两个线程同时写文件。 */
    private static volatile boolean downloading = false;
    /** 下载进度弹窗（全程可见，不再静默失败）。 */
    private static volatile AlertDialog progressDlg = null;
    /** 进度节流：最多每 400ms 刷一次 UI。 */
    private static volatile int lastPct = -1;
    private static volatile long lastPctAt = 0;

    /** 更新流程的每一步都会推给页面日志栏（MainActivity 接）。 */
    public interface Listener {
        void log(String msg);
    }

    private static volatile Listener listener;

    public static void setListener(Listener l) {
        listener = l;
    }

    private UpdateManager() {
    }

    private static void log(String msg) {
        Listener l = listener;
        if (l != null) l.log(msg);
    }

    /** 后台查一次更新；有新版本就在主线程弹框。失败静默。 */
    public static void check(final Activity activity) {
        new Thread(() -> {
            try {
                HttpURLConnection c = (HttpURLConnection) new URL(API).openConnection();
                c.setConnectTimeout(8000);
                c.setReadTimeout(8000);
                c.setRequestProperty("Accept", "application/vnd.github+json");
                c.setRequestProperty("User-Agent", "dsh-remote-updater");
                if (c.getResponseCode() != 200) return;

                StringBuilder sb = new StringBuilder();
                BufferedReader r = new BufferedReader(new InputStreamReader(c.getInputStream()));
                String line;
                while ((line = r.readLine()) != null) sb.append(line);
                r.close();

                JSONObject json = new JSONObject(sb.toString());
                String tag = json.optString("tag_name", "");
                if (!tag.startsWith("build-")) return;

                int remote;
                try {
                    remote = Integer.parseInt(tag.substring("build-".length()));
                } catch (Exception e) {
                    return;
                }

                int local;
                try {
                    local = activity.getPackageManager()
                            .getPackageInfo(activity.getPackageName(), 0).versionCode;
                } catch (Exception e) {
                    return;
                }
                if (remote <= local) return;

                String apkUrl = null;
                JSONArray assets = json.optJSONArray("assets");
                if (assets != null) {
                    for (int i = 0; i < assets.length(); i++) {
                        JSONObject a = assets.getJSONObject(i);
                        if (a.optString("name", "").endsWith(".apk")) {
                            apkUrl = a.optString("browser_download_url", null);
                            break;
                        }
                    }
                }
                if (apkUrl == null) return;

                final String url = apkUrl;
                final int ver = remote;
                activity.runOnUiThread(() -> prompt(activity, ver, url));
            } catch (Exception ignored) {
            }
        }).start();
    }

    private static void prompt(final Activity a, final int ver, final String url) {
        if (a.isFinishing()) return;
        new AlertDialog.Builder(a)
                .setTitle("发现新版本")
                .setMessage("build-" + ver + " 已经编译好了，现在下载安装？\n（会覆盖当前版本，配对信息保留）")
                .setPositiveButton("下载更新", (d, w) -> startDownload(a, url, 1))
                .setNeutralButton("浏览器下载", (d, w) -> openInBrowser(a, url))
                .setNegativeButton("稍后", null)
                .show();
    }

    /** 自建 HTTP 下载（绕开小米迅雷引擎），失败自动重试，最后开浏览器直接下 APK 兜底。 */
    private static void startDownload(final Activity a, final String url, final int attempt) {
        if (downloading) return;
        downloading = true;
        new Thread(() -> {
            boolean ok = false;
            String failReason = "未知错误";
            try {
                File dir = a.getExternalFilesDir(null);
                if (dir == null) throw new Exception("无法创建下载目录");
                File out = new File(dir, "update.apk");
                if (out.exists()) out.delete(); // 每次下载前清掉旧包，避免残留垃圾
                showProgress(a, "正在下载（第 " + attempt + "/" + MAX_DOWNLOAD_ATTEMPTS + " 次尝试）…");
                log("开始下载: " + url);
                long bytes = httpDownload(url, out, a, attempt);
                if (bytes > 0) {
                    ok = true;
                    log("下载完成: " + bytes + " 字节");
                    hideProgress(a);
                    toast(a, "下载完成（" + bytes / 1024 + " KB），正在安装…");
                    install(a, out);
                } else {
                    throw new Exception("0 字节");
                }
            } catch (Exception e) {
                failReason = (e.getMessage() == null) ? "下载异常" : e.getMessage();
                log("下载失败: " + failReason);
            } finally {
                downloading = false;
            }

            if (ok) return;

            if (attempt < MAX_DOWNLOAD_ATTEMPTS) {
                showProgress(a, "下载失败（" + failReason + "），3 秒后自动重试\n第 " + (attempt + 1) + "/" + MAX_DOWNLOAD_ATTEMPTS + " 次…");
                sleep(3000);
                if (a.isFinishing()) {
                    hideProgress(a);
                    return;
                }
                startDownload(a, url, attempt + 1);
            } else {
                hideProgress(a);
                toast(a, "自动下载 4 次都失败，已打开浏览器直接下载 APK");
                log("自动下载失败，打开浏览器: " + url);
                openInBrowser(a, url);
            }
        }).start();
    }

    /** 手动跟随重定向 + 超时流式下载到 out；返回下载字节数，异常/0 字节会抛错。 */
    private static long httpDownload(String url, File out, Activity a, int attempt) throws Exception {
        String current = url;
        for (int hop = 0; hop < 6; hop++) {
            HttpURLConnection c = (HttpURLConnection) new URL(current).openConnection();
            c.setConnectTimeout(CONNECT_TIMEOUT);
            c.setReadTimeout(READ_TIMEOUT);
            c.setInstanceFollowRedirects(false); // 自己处理跨域重定向
            c.setRequestProperty("User-Agent", "dsh-remote-updater");

            int code = c.getResponseCode();
            if (code == 301 || code == 302 || code == 303 || code == 307 || code == 308) {
                String loc = c.getHeaderField("Location");
                c.disconnect();
                if (loc == null) throw new Exception("重定向没有 Location");
                current = new URL(new URL(current), loc).toString();
                continue;
            }
            if (code != 200) {
                c.disconnect();
                throw new Exception("HTTP " + code);
            }

            long total = c.getContentLengthLong();
            InputStream in = c.getInputStream();
            FileOutputStream fos = new FileOutputStream(out);
            byte[] buf = new byte[8192];
            long got = 0;
            int n;
            int lastShown = -1000;
            try {
                while ((n = in.read(buf)) != -1) {
                    fos.write(buf, 0, n);
                    got += n;
                    if (total > 0) {
                        int pct = (int) (got * 100 / total);
                        if (pct != lastShown) {
                            lastShown = pct;
                            showPct(a, pct, attempt);
                        }
                    }
                }
            } finally {
                try {
                    in.close();
                } catch (Exception ignored) {
                }
                try {
                    fos.close();
                } catch (Exception ignored) {
                }
                c.disconnect();
            }
            if (got <= 0) throw new Exception("0 字节");
            if (total > 0 && got != total) throw new Exception("不完整: " + got + "/" + total);
            return got;
        }
        throw new Exception("重定向太多");
    }

    /** 进度节流刷新：弹窗里显示百分比，日志里每 25% 记一条。 */
    private static void showPct(Activity a, int pct, int attempt) {
        long now = System.currentTimeMillis();
        if (now - lastPctAt < 400) return; // 最多每 400ms 刷一次，避免刷爆 UI
        if (pct == lastPct) return;
        lastPct = pct;
        lastPctAt = now;
        showProgress(a, "正在下载 " + pct + "%（第 " + attempt + "/" + MAX_DOWNLOAD_ATTEMPTS + " 次尝试）");
        if (pct % 25 == 0) log("下载进度 " + pct + "%");
    }

    /** 启动时清理超过 24 小时的旧更新包，避免一直占空间。 */
    public static void cleanupStale(Activity a) {
        try {
            File dir = a.getExternalFilesDir(null);
            if (dir == null) return;
            File f = new File(dir, "update.apk");
            if (f.exists() && System.currentTimeMillis() - f.lastModified() > 24L * 3600 * 1000) {
                if (f.delete()) log("已清理旧的更新包（超过 24 小时）");
            }
        } catch (Exception ignored) {
        }
    }

    private static void showProgress(Activity a, String msg) {
        a.runOnUiThread(() -> {
            if (a.isFinishing()) return;
            try {
                if (progressDlg == null) {
                    progressDlg = new AlertDialog.Builder(a)
                            .setTitle("下载更新")
                            .setCancelable(true)
                            .create();
                }
                progressDlg.setMessage(msg);
                if (!progressDlg.isShowing()) progressDlg.show();
            } catch (Exception ignored) {
            }
        });
    }

    private static void hideProgress(Activity a) {
        a.runOnUiThread(() -> {
            try {
                if (progressDlg != null && progressDlg.isShowing()) progressDlg.dismiss();
                progressDlg = null;
            } catch (Exception ignored) {
            }
        });
    }

    private static void install(Activity a, File apk) {
        try {
            // Android 8+ 需要用户授权"安装未知应用"
            if (Build.VERSION.SDK_INT >= 26 && !a.getPackageManager().canRequestPackageInstalls()) {
                Intent s = new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                        Uri.parse("package:" + a.getPackageName()));
                a.startActivity(s);
                return;
            }

            Intent i = new Intent(Intent.ACTION_VIEW);
            i.setDataAndType(Uri.parse("content://" + ApkProvider.AUTHORITY + "/update.apk"),
                    "application/vnd.android.package-archive");
            i.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            a.startActivity(i);
        } catch (Exception ignored) {
        }
    }

    private static void openInBrowser(Activity a, String url) {
        try {
            Intent i = new Intent(Intent.ACTION_VIEW, Uri.parse(url));
            i.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
            a.startActivity(i);
        } catch (Exception ignored) {
        }
    }

    private static void toast(Activity a, String msg) {
        try {
            a.runOnUiThread(() -> Toast.makeText(a, msg, Toast.LENGTH_SHORT).show());
        } catch (Exception ignored) {
        }
    }

    private static void sleep(long ms) {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException ignored) {
        }
    }
}
