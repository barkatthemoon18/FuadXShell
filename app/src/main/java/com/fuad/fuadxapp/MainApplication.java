package com.fuad.fuadxapp;

import android.app.Application;
import android.content.Context;
import android.os.Build;
import android.util.Log;

import com.fuad.fuadx.FuadX;
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
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        app = this;
        FuadX.attachBaseContext(base);
    }

    @Override
    public void onCreate() {
        boolean started;

        super.onCreate();
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
