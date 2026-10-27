package com.dsh.remote;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Intent;
import android.os.Build;
import android.os.IBinder;

/**
 * 前台服务：让进程在切后台时不被系统冻结/回收，WebView 里的 WebSocket 才有机会继续活着。
 * 用 dataSync 类型（Android 14 要求显式声明），通知常驻。
 */
public class KeepAliveService extends Service {

    private static final String CHANNEL_ID = "dsh_remote_keepalive";
    private static final int NOTIFY_ID = 4210;

    @Override
    public void onCreate() {
        super.onCreate();

        NotificationManager nm = (NotificationManager) getSystemService(NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= 26 && nm != null) {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID, "远控连接", NotificationManager.IMPORTANCE_LOW);
            ch.setDescription("保持与电脑的连接");
            nm.createNotificationChannel(ch);
        }

        Notification n;
        if (Build.VERSION.SDK_INT >= 26) {
            n = new Notification.Builder(this, CHANNEL_ID)
                    .setContentTitle("大肥鱼远控")
                    .setContentText("保持连接中")
                    .setSmallIcon(android.R.drawable.stat_notify_sync)
                    .setOngoing(true)
                    .build();
        } else {
            n = new Notification.Builder(this)
                    .setContentTitle("大肥鱼远控")
                    .setContentText("保持连接中")
                    .setSmallIcon(android.R.drawable.stat_notify_sync)
                    .setOngoing(true)
                    .build();
        }
        startForeground(NOTIFY_ID, n);
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
