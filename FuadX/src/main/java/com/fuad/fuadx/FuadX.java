package com.fuad.fuadx;

import android.content.Context;
import android.util.Log;

import com.fuad.fuadx.detection.runtime.FuadXBootstrap;
import com.fuad.fuadx.detection.runtime.ProcessScope;

import java.util.Objects;

public final class FuadX {
    private static final String TAG = "FuadX";
    private static final Object LOCK = new Object();
    private static FuadXBootstrap bootstrap;
    private static FuadXBootstrap.State inactiveState = FuadXBootstrap.State.NEW;

    private FuadX() {
        /* Empty intentionally */
    }

    public static void attachBaseContext(Context context) {
        ProcessScope scope;

        Objects.requireNonNull(context, "context");
        synchronized (LOCK) {
            if (bootstrap != null || inactiveState != FuadXBootstrap.State.NEW) {
                return;
            }
            scope = ProcessScope.resolve(context);
            if (scope == ProcessScope.SECONDARY) {
                inactiveState = FuadXBootstrap.State.SKIPPED;
                Log.i(TAG, "Skipping full RASP runtime in secondary process");
                return;
            }
            if (scope == ProcessScope.UNKNOWN) {
                inactiveState = FuadXBootstrap.State.FAILED;
                Log.e(TAG, "Unable to identify application process");
                return;
            }
            bootstrap = new FuadXBootstrap(context);
            bootstrap.start();
        }
    }

    public static FuadXBootstrap.State getState() {
        synchronized (LOCK) {
            if (bootstrap == null) {
                return inactiveState;
            }
            return bootstrap.getState();
        }
    }
}
