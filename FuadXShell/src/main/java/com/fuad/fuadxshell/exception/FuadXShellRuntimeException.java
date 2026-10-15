package com.fuad.fuadxshell.exception;

import android.content.Context;
import android.content.Intent;
import android.util.Log;

import com.fuad.fuadxshell.RaspActivity;
import com.fuad.fuadxshell.report.FuadXShellTombstone;

public class FuadXShellRuntimeException extends RuntimeException {
    private static final String TAG = "FuadXShellRuntimeException";
    private final String module;
    private final String details;
    private final int errorCode;

    public FuadXShellRuntimeException(Context ctx, String module, String message, String details,
                                      int errorCode) {
        super(message);
        this.module = module;
        this.details = details;
        this.errorCode = errorCode;
        FuadXShellTombstone tombstone = new FuadXShellTombstone(module, message, details, errorCode,
                new Throwable().getStackTrace());
        tombstone.save(ctx);
        Log.e(TAG, tombstone.getTombstone(ctx));
        Intent intent = new Intent(ctx, RaspActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        intent.putExtra("message", details);
        ctx.startActivity(intent);
    }

    public String getModule() { return module; }

    public String getDetails() { return details; }

    public int getErrorCode() { return errorCode; }
}
