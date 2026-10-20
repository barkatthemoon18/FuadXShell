package com.fuad.fuadxapp;

import android.app.Application;
import android.content.Context;

import com.fuad.fuadx.FuadX;
import com.fuad.fuadx.detection.reporting.PersistentDetectionReporter;
import com.fuad.fuadx.detection.runtime.FuadXRuntime;

public class MainApplication extends Application {
    private static final String TAG = "FuadXApp";
    public static Application app;


    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        app = this;
        FuadX.attachBaseContext(base);
    }

    @Override
    public void onCreate() {
        super.onCreate();
    }
}
