package com.fuad.fuadxapp;

import android.content.ComponentName;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.Build;
import android.os.Bundle;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.fuad.fuadx.IWatcherSvc;
import com.fuad.fuadx.WatcherSvc;
import com.fuad.fuadx.apkintegrity.ApkIntegrity;
import com.fuad.fuadx.debug.Debug;
import com.fuad.fuadx.frida.Frida;
import com.fuad.fuadx.handler.FuadXHandler;
import com.fuad.fuadx.logger.FuadXLogger;
import com.fuad.fuadx.pinning.SSLPinning;
import com.fuad.fuadx.util.AndroidUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

public class MainActivity extends AppCompatActivity {
    String TAG = "FuadXApp";
    private final ServiceConnection watcherSvcConnectionBinder = new ServiceConnection() {
        @Override
        public void onServiceConnected(ComponentName name, IBinder service) {
            IWatcherSvc watcherSvcBinder = IWatcherSvc.Stub.asInterface(service);
            try {
                String result = watcherSvcBinder.svc();
                Log.e(TAG, "Return: " + result);
            }
            catch (RemoteException e) {
                Log.e(TAG, "Error: " + e.getMessage(), e);
            }
        }

        @Override
        public void onServiceDisconnected(ComponentName name) {
            Log.i(TAG, "Bound service disconnected");
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });
        /* Process proc = null;
        try {
            proc = Runtime.getRuntime().exec("df");

            try (InputStream is = proc.getInputStream();
                 BufferedReader br = new BufferedReader(
                         new InputStreamReader(is, StandardCharsets.UTF_8))) {

                String line;
                while ((line = br.readLine()) != null) {
                    Log.e(TAG, "Mount line: " + line);
                    String lower = line.toLowerCase();
                    if (lower.contains("magisk") || lower.contains("magisk")) {
                        Log.e(TAG, "Found magisk at: " + line);
                    }
                }
            }
            // Esperamos a que el proceso salga para no dejar zombies
            proc.waitFor();
        } catch (IOException | InterruptedException e) {
            // Puedes registrar en logcat si lo necesitas
            Log.e(TAG, "Error: " + e);
        } finally {
            if (proc != null) {
                proc.destroy();
            }
        } */
        // getApplicationContext().bindService(new Intent(this, WatcherSvc.class), watcherSvcConnectionBinder, BIND_AUTO_CREATE);
        /* Log.e(TAG, "Test apk name: " + AndroidUtil.getCmdlinePackageName());
        Log.e(TAG, "Is App Debuggable: " + ApkIntegrity.checkAndroidManifest(getApplicationContext()));
        Log.e(TAG, "Is APK Signature verified: " + ApkIntegrity.isApkStaticallySecure(getApplicationContext()));
        Log.e(TAG, "Is APK Signature verified V1: " + ApkIntegrity.verifyCertificateV1(getApplicationContext()));
        Log.e(TAG, "Is APK Signature verified V2 Onwards: " + ApkIntegrity.verifyCertificateV2Onwards(getApplicationContext()));
        getApplicationContext().bindService(new Intent(this, com.fuad.fuadx.WatcherSvc.class), watcherSvcConnectionBinder, BIND_AUTO_CREATE);
        Frida.isRunningFridaOnApk();
        Debug.isRunningDebugOnApk();
        SSLPinning.isAppPinned(getApplicationContext());  */
        // FuadXLogger.configure(getApplicationContext());
        // FuadXLogger.log().debug(TAG, "FuadX Logger configured and working");
        /*ApkIntegrity.isApkStaticallySecured(this); */
        // FuadXHandler.init(getApplicationContext());
        Log.e(TAG, "Finished");
    }
}