package com.fuad.fuadxshell;

import android.app.Application;
import android.content.Context;
import android.util.Log;
import dalvik.system.*;

import com.fuad.fuadxshell.exception.FuadXShellRuntimeException;

import java.io.IOException;

public class MainApplication extends Application {
    public static Application app;

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        app = this;
        try {
            System.loadLibrary("fuadxshell");
        }
        catch (Exception e) {
            throw new FuadXShellRuntimeException(base, "FuadXShell", "Failed to run app",
                    e.getMessage(), -1000);
        }
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