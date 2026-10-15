package com.fuad.fuadx.detection;

import android.content.Context;

import java.util.Objects;

public final class DetectionContext {
    private final Context appContext;

    public DetectionContext(Context appContext) {
        Objects.requireNonNull(appContext);

        this.appContext = appContext.getApplicationContext() != null ?
                appContext.getApplicationContext() : appContext;
    }

    public Context getApplicationContext() {
        return appContext;
    }
}
