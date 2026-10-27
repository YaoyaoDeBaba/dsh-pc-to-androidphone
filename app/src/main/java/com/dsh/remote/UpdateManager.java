package com.dsh.remote;

import android.app.Activity;
import android.app.AlertDialog;
import android.app.DownloadManager;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * 自更新：查最新 Release -> 版本更高就问用户 -> 系统 DownloadManager 下载 -> 直接拉起安装器。
 *
 * 国内访问 GitHub 下载 CDN 时通时不通，所以下载失败会自动重试几次；
 * 实在不行就引导到浏览器里下（浏览器对这块网络更耐造）。
 * 不引 androidx / FileProvider：安装用 DownloadManager 自己的 content URI，保持零依赖。
 */
public final class UpdateManager {

    private static final String OWNER = "YaoyaoDeBaba";
    private static final String REPO = "dsh-pc-to-androidphone";
    private static final String API =
            "https://api.github.com/repos/" + OWNER + "/" + REPO + "/releases/latest";
    private static final String RELEASES_PAGE =
            "https://github.com/" + OWNER + "/" + REPO + "/releases/latest";
    /** 下载失败自动重试次数上限（每次间隔 3 秒）。 */
    private static final int MAX_DOWNLOAD_ATTEMPTS = 4;

    private UpdateManager() {
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
                .setPositiveButton("下载更新", (d, w) -> download(a, url, 1))
                .setNeutralButton("浏览器下载", (d, w) -> openInBrowser(a, RELEASES_PAGE))
                .setNegativeButton("稍后", null)
                .show();
    }

    private static void download(final Activity a, final String url, final int attempt) {
        final DownloadManager dm = (DownloadManager) a.getSystemService(Context.DOWNLOAD_SERVICE);
        if (dm == null) return;

        DownloadManager.Request req = new DownloadManager.Request(Uri.parse(url))
                .setTitle("大肥鱼远控")
                .setDescription("正在下载更新（第 " + attempt + " 次尝试）…")
                .setNotificationVisibility(DownloadManager.Request.VISIBILITY_VISIBLE
                        | DownloadManager.Request.VISIBILITY_VISIBLE_NOTIFY_COMPLETED);

        final long id = dm.enqueue(req);

        BroadcastReceiver receiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context ctx, Intent intent) {
                long got = intent.getLongExtra(DownloadManager.EXTRA_DOWNLOAD_ID, -1);
                if (got != id) return;
                try {
                    a.unregisterReceiver(this);
                } catch (Exception ignored) {
                }
                handleResult(a, dm, id, url, attempt);
            }
        };
        a.registerReceiver(receiver, new IntentFilter(DownloadManager.ACTION_DOWNLOAD_COMPLETE));
    }

    private static void handleResult(Activity a, DownloadManager dm, long id, String url, int attempt) {
        try {
            int status = 0;
            DownloadManager.Query q = new DownloadManager.Query().setFilterById(id);
            try (Cursor c = dm.query(q)) {
                if (c != null && c.moveToFirst()) {
                    status = c.getInt(c.getColumnIndexOrThrow(DownloadManager.COLUMN_STATUS));
                }
            }

            if (status == DownloadManager.STATUS_SUCCESSFUL) {
                install(a, dm, id);
                return;
            }

            // 下载失败：CDN 在国内时通时不通，自动重试几次
            if (attempt < MAX_DOWNLOAD_ATTEMPTS) {
                toast(a, "下载失败，自动重试（" + attempt + "/" + MAX_DOWNLOAD_ATTEMPTS + "）…");
                new Handler(Looper.getMainLooper()).postDelayed(() -> {
                    if (!a.isFinishing()) download(a, url, attempt + 1);
                }, 3000);
            } else {
                toast(a, "自动下载失败，已打开浏览器，点 app-debug.apk 即可下载");
                openInBrowser(a, RELEASES_PAGE);
            }
        } catch (Exception ignored) {
        }
    }

    private static void install(Activity a, DownloadManager dm, long id) {
        try {
            Uri apkUri = dm.getUriForDownloadedFile(id);
            if (apkUri == null) return;

            // Android 8+ 需要用户授权"安装未知应用"
            if (Build.VERSION.SDK_INT >= 26 && !a.getPackageManager().canRequestPackageInstalls()) {
                Intent s = new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                        Uri.parse("package:" + a.getPackageName()));
                a.startActivity(s);
                return;
            }

            Intent i = new Intent(Intent.ACTION_VIEW);
            i.setDataAndType(apkUri, "application/vnd.android.package-archive");
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
            Toast.makeText(a, msg, Toast.LENGTH_LONG).show();
        } catch (Exception ignored) {
        }
    }
}
