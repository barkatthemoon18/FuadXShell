package com.fuad.fuadxshell;

import android.app.Application;
import android.content.Context;
import android.util.Log;
import dalvik.system.*;

import com.fuad.fuadxshell.exception.FuadXShellRuntimeException;

public class MainApplication extends Application {
    public static Application app;

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        app = this;
    }

    @Override
    public void onCreate() {
        super.onCreate();
        try {
            load();
        }
        catch (FuadXShellRuntimeException e) {
            Log.e("FuadXShell", "Error while loading app: " + e.getMessage(), e);
        }
    }

    private static native synchronized void load();
}