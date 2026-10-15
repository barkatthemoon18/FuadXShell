package com.fuad.fuadx;

import android.app.Application;
import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.util.Log;

import androidx.annotation.Nullable;

import com.fuad.fuadx.reflection.Reflection;
import com.fuad.fuadx.root.Root;

import java.lang.reflect.Method;

public class WatcherSvc extends Service {
    private static final String TAG = "WatcherSvc";

    private final IWatcherSvc.Stub watcherSvcBinder = new IWatcherSvc.Stub() {
        @Override
        public String svc() {
            try {
                Method currentActivityThreadMethod = Reflection.getMethod("android.app.ActivityThread",
                        "currentActivityThread");
                Object activityThreadObject = currentActivityThreadMethod.invoke(null);
                Method getApplicationMethod = Reflection.getMethod("android.app.ActivityThread",
                        "getApplication");
                Application applicationContext = (Application)
                        getApplicationMethod.invoke(activityThreadObject);
                return Root.runProbe(applicationContext);
            }
            catch (Exception e) {
                Log.e(TAG, "Error: " + e.getMessage(), e);
                return "false";
            }
        }
    };

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return watcherSvcBinder;
    }
}