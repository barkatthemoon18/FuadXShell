package com.fuad.fuadx.report;

import android.content.Context;
import android.os.Build;
import android.provider.Settings;
import android.util.Log;

import com.fuad.fuadx.Constants;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.Serializable;
import java.security.MessageDigest;
import java.util.UUID;

public class FuadXTombstone implements Serializable {
    private static final String TAG = "FuadXTombstone";
    private static final Gson gson = new GsonBuilder().disableHtmlEscaping()
            .setPrettyPrinting().create();
    private final String module;
    private final long timestamp;
    private final String message;
    private final String details;
    private final int errorCode;
    private final String[] stackTrace;

    public FuadXTombstone(String module, String message, String details, int errorCode,
                          StackTraceElement[] stackTrace) {
        this.module = module;
        this.timestamp = System.currentTimeMillis();
        this.message = message;
        this.details = details;
        this.errorCode = errorCode;
        this.stackTrace = serializeStackTrace(stackTrace);
    }

    public synchronized void save(Context ctx) {
        try {
            TombstoneDevicePayload tombstoneDevicePayload =
                    new FuadXTombstone.TombstoneDevicePayload(ctx, this);
            File dir = new File(ctx.getFilesDir(), Constants.TOMBSTONE_DIRECTORY);
            if (!dir.exists()) {
                dir.mkdirs();
            }
            File file = new File(dir, Constants.TOMBSTONE_FILE_NAME +
                    System.currentTimeMillis() + Constants.TOMBSTONE_FILE_EXTENSION);
            try (FileOutputStream fos = new FileOutputStream(file)) {
                fos.write(gson.toJson(tombstoneDevicePayload).getBytes());
            }
        }
        catch (Exception e) {
            Log.e(TAG, "Error saving tombstone: " + e.getMessage(), e);
        }
    }

    private String[] serializeStackTrace(StackTraceElement[] stackTrace) {
        String[] serializedStackTrace = new String[stackTrace.length];
        for (int i = 0; i < stackTrace.length; i++) {
            serializedStackTrace[i] = stackTrace[i].toString();
        }
        return serializedStackTrace;
    }

    public String getTombstone(Context ctx) {
        TombstoneDevicePayload tombstoneDevicePayload =
                new FuadXTombstone.TombstoneDevicePayload(ctx, this);
        return gson.toJson(tombstoneDevicePayload);
    }

    static class TombstoneDevicePayload {
        String appId;
        final String deviceId;
        final String deviceModel;
        final String deviceName;
        final String deviceManufacturer;
        final int sdkVersion;
        final FuadXTombstone tombstone;

        public TombstoneDevicePayload(Context ctx, FuadXTombstone tombstone) {
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-256");
                this.appId = UUID.nameUUIDFromBytes(md.digest(ctx.getPackageName()
                        .getBytes())).toString();
            }
            catch (Exception e) {
                Log.e(TAG, "Unable to retrieve appId: " + e.getMessage());
                this.appId = "";
            }
            this.deviceId = UUID.nameUUIDFromBytes(Settings.Secure.ANDROID_ID.getBytes()).toString();
            this.deviceModel = Build.DEVICE;
            this.deviceName = Build.MODEL;
            this.deviceManufacturer = Build.MANUFACTURER;
            this.sdkVersion = Build.VERSION.SDK_INT;
            this.tombstone = tombstone;
        }
    }
}
