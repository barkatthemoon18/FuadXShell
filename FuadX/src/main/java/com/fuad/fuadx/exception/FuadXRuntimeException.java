package com.fuad.fuadx.exception;

import android.content.Context;
import android.util.Log;

import com.fuad.fuadx.report.FuadXTombstone;

public class FuadXRuntimeException extends RuntimeException {
    private static final String TAG = "FuadXRuntimeException";
    private final String module;
    private final String details;
    private final int errorCode;

    public FuadXRuntimeException(Context ctx, String module, String message, String details,
                                 int errorCode) {
        super(message);
        this.module = module;
        this.details = details;
        this.errorCode = errorCode;
        FuadXTombstone tombstone = new FuadXTombstone(module, message, details, errorCode,
                new Throwable().getStackTrace());
        tombstone.save(ctx);
        Log.e(TAG, tombstone.getTombstone(ctx));
    }

    public String getModule() {
        return module;
    }

    public String getDetails() {
        return details;
    }

    public int getErrorCode() {
        return errorCode;
    }
}
