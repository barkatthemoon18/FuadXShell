package com.fuad.fuadx.detection.runtime;

import android.app.Application;
import android.content.Context;
import android.os.Build;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

public enum ProcessScope {
    MAIN,
    SECONDARY,
    UNKNOWN;

    private static final String TAG = "FuadXProcess";

    public static ProcessScope resolve(Context context) {
        String expected;
        String actual;

        Objects.requireNonNull(context, "context");
        expected = context.getApplicationInfo().processName;

        if (expected == null || expected.isEmpty()) {
            expected = context.getPackageName();
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            actual = Application.getProcessName();
        }
        else {
            actual = readProcessName();
        }
        return classify(actual, expected);
    }

    static ProcessScope classify(String actual, String expected) {
        if (actual == null || actual.isEmpty() || expected == null || expected.isEmpty()) {
            return UNKNOWN;
        }
        return actual.equals(expected) ? MAIN : SECONDARY;
    }

    private static String readProcessName() {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        int value;

        try (FileInputStream fis = new FileInputStream("/proc/self/cmdline")) {
            for (int i = 0; i < 256; i++) {
                value = fis.read();
                if (value <= 0) {
                    break;
                }
                buffer.write(value);
            }
            return buffer.toString(StandardCharsets.UTF_8.name());
        }
        catch (IOException e) {
            Log.e(TAG, "Unable to resolve process name", e);
            return null;
        }
    }
}
