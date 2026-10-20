package com.fuad.fuadxapp;

import android.app.Application;
import android.os.Build;
import android.util.Log;

import com.fuad.fuadx.detection.policy.MonitoringDetectionPolicy;
import com.fuad.fuadx.detection.reporting.PersistentDetectionReporter;
import com.fuad.fuadx.detection.runtime.FuadXRuntime;
import com.fuad.fuadx.module.ModuleId;

import java.io.FileInputStream;
import java.io.IOException;

public class MainApplication extends Application {
    private static final String TAG = "FuadXApp";
    public static Application app;
    private FuadXRuntime raspRuntime;
    private PersistentDetectionReporter detectionReporter;


    @Override
    public void onCreate() {
        boolean started;

        super.onCreate();
        if (!isMainProcess()) {
            Log.i(TAG, "Skipping RASP initialization in secondary process");
            return;
        }
        detectionReporter = new PersistentDetectionReporter(getApplicationContext());
        raspRuntime = new FuadXRuntime(getApplicationContext(),
                result -> Log.i(TAG, "RASP module: " + result.getModuleId() +
                        ", status: " + result.getStatus() + ", evidence: " + result.getEvidence().size()
                        + ", diagnostics: " + result.getDiagnostics().size()),
                new MonitoringDetectionPolicy(), detectionReporter);
        started = raspRuntime.start(ModuleId.FRIDA, 5000);
        Log.i(TAG, "Frida scheduled: " + started);
    }

    private boolean isMainProcess() {
        String processName;
        StringBuilder builder;
        int value;

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            processName = Application.getProcessName();
            return getPackageName().equals(processName);
        }
        else {
            builder = new StringBuilder();
            try (FileInputStream fis = new FileInputStream("/proc/self/cmdline")) {
                while ((value = fis.read()) > 0) {
                    builder.append((char) value);
                }
                processName = builder.toString();
            }
            catch (IOException e) {
                Log.e(TAG, "Unable to identify current process", e);
                return false;
            }
            return getPackageName().equals(processName);
        }
    }

    public synchronized void stopRasp() {
        if (raspRuntime != null) {
            raspRuntime.close();
            raspRuntime = null;
        }
        if (detectionReporter != null) {
            detectionReporter.close();
            detectionReporter = null;
        }
    }
}
