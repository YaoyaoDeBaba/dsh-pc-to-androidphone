package com.dsh.remote;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;

/**
 * 大肥鱼远控 —— 极薄的 WebView 外壳。
 *
 * 所有业务逻辑都在 assets/index.html + assets/app.js 里（用官方协议包做加密和组帧）。
 * 这样在 GitHub Actions 里编译时不需要 Kotlin、不需要任何第三方依赖，构建最稳。
 */
public class MainActivity extends Activity {

    private WebView webView;
    private long lastUpdateCheck = 0;

    /** 打开/回到前台时检查更新；30 秒内不重复弹，避免叠弹窗。 */
    private void checkUpdateIfStale() {
        long now = System.currentTimeMillis();
        if (now - lastUpdateCheck < 30_000) return;
        lastUpdateCheck = now;
        UpdateManager.check(this);
    }

    @SuppressLint("SetJavaScriptEnabled")
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        webView = new WebView(this);
        webView.setBackgroundColor(Color.parseColor("#12121c"));
        setContentView(webView);

        WebSettings s = webView.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setDatabaseEnabled(true);
        s.setAllowFileAccess(true);
        s.setAllowContentAccess(true);
        // 允许 file:// 页面连接 wss:// 中继（WebSocket 不走同源限制，但有些 WebView 版本需要这个）
        s.setAllowUniversalAccessFromFileURLs(true);
        s.setMediaPlaybackRequiresUserGesture(false);
        s.setCacheMode(WebSettings.LOAD_DEFAULT);

        webView.setWebViewClient(new WebViewClient());

        webView.loadUrl("file:///android_asset/index.html");

        // 前台服务保活：切后台时尽量不让系统冻结 WebView 与 WebSocket
        try {
            Intent svc = new Intent(this, KeepAliveService.class);
            if (android.os.Build.VERSION.SDK_INT >= 26) {
                startForegroundService(svc);
            } else {
                startService(svc);
            }
        } catch (Exception ignored) {
        }

        // 页面上的「更新」按钮走这里
        webView.addJavascriptInterface(new Object() {
            @android.webkit.JavascriptInterface
            public void checkUpdate() {
                runOnUiThread(() -> UpdateManager.check(MainActivity.this));
            }
        }, "dshApp");

        // 启动时静默查一次有没有新版本
        checkUpdateIfStale();
    }

    @Override
    protected void onResume() {
        super.onResume();
        // 每次回到前台都看看有没有新版本（会话页的「更新」按钮也能手动触发）
        checkUpdateIfStale();
    }

    @Override
    public void onBackPressed() {
        if (webView != null && webView.canGoBack()) {
            webView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    @Override
    protected void onDestroy() {
        if (webView != null) {
            webView.destroy();
            webView = null;
        }
        super.onDestroy();
    }
}
