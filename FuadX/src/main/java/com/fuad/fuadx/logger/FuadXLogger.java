package com.fuad.fuadx.logger;

import android.content.Context;
import android.os.Build;
import android.util.Log;

import com.fuad.fuadx.Constants;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public class FuadXLogger {
    private static final String TAG = "FuadXLogger";
    private static final FuadXLogger INSTANCE = new FuadXLogger();
    private static File logFile;

    private FuadXLogger() {
        /* Empty intentionally */
    }

    public static FuadXLogger log() {
        return INSTANCE;
    }

    public static void configure(Context ctx) {
        String buildLogFileName;

        if (ctx == null) {
            throw new IllegalArgumentException("Context cannot be null");
        }
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) {
            Date date = new Date();
            SimpleDateFormat dateFormat = new SimpleDateFormat(Constants.LOG_DATE_PATTERN,
                    Locale.getDefault());
            buildLogFileName = Constants.LOG_FILE_NAME + dateFormat.format(date) +
                    Constants.LOG_FILE_EXTENSION;
        }
        else {
            buildLogFileName = Constants.LOG_FILE_NAME + LocalDateTime.now()
                    .format(DateTimeFormatter.ofPattern(Constants.LOG_DATE_PATTERN)) +
                    Constants.LOG_FILE_EXTENSION;
        }
        File logDirectory = new File(ctx.getFilesDir(), Constants.LOG_DIRECTORY);
        if (!logDirectory.exists()) {
            logDirectory.mkdirs();
        }
        logFile = new File(logDirectory, buildLogFileName);
        try (FileOutputStream fos = new FileOutputStream(logFile, true)) {
            String header = "FuadX Logger for: " + ctx.getPackageName() + "\n";
            fos.write(header.getBytes());
        }
        catch (Exception e) {
            throw new RuntimeException("Failed to create log file", e);
        }
    }

    public void debug(String tag, String message) {
        FuadXLogEntry entry = new FuadXLogEntry(tag, message, LogLevel.DEBUG);
        saveLoggedEntry(entry);
    }

    public void debug(String tag, String message, Map<String, Object> metadata) {
        FuadXLogEntry entry = new FuadXLogEntry(tag, message, LogLevel.DEBUG, metadata);
        saveLoggedEntry(entry);
    }

    public void info(String tag, String message) {
        FuadXLogEntry entry = new FuadXLogEntry(tag, message, LogLevel.INFO);
        saveLoggedEntry(entry);
    }

    public void info(String tag, String message, Map<String, Object> metadata) {
        FuadXLogEntry entry = new FuadXLogEntry(tag, message, LogLevel.INFO, metadata);
        saveLoggedEntry(entry);
    }

    public void warn(String tag, String message) {
        FuadXLogEntry entry = new FuadXLogEntry(tag, message, LogLevel.WARNING);
        saveLoggedEntry(entry);
    }

    public void warn(String tag, String message, Map<String, Object> metadata) {
        FuadXLogEntry entry = new FuadXLogEntry(tag, message, LogLevel.WARNING, metadata);
        saveLoggedEntry(entry);
    }

    public void error(String tag, String message) {
        FuadXLogEntry entry = new FuadXLogEntry(tag, message, LogLevel.ERROR);
        saveLoggedEntry(entry);
    }

    public void error(String tag, String message, Map<String, Object> metadata) {
        FuadXLogEntry entry = new FuadXLogEntry(tag, message, LogLevel.ERROR, metadata);
        saveLoggedEntry(entry);
    }

    public void fatal(String tag, String message) {
        FuadXLogEntry entry = new FuadXLogEntry(tag, message, LogLevel.FATAL);
        saveLoggedEntry(entry);
    }

    public void fatal(String tag, String message, Map<String, Object> metadata) {
        FuadXLogEntry entry = new FuadXLogEntry(tag, message, LogLevel.FATAL, metadata);
        saveLoggedEntry(entry);
    }

    private synchronized void saveLoggedEntry(FuadXLogEntry entry) {
        File destination;
        byte[] payload;

        Objects.requireNonNull(entry, "entry");
        destination = logFile;
        if (destination == null) {
            Log.w(TAG, "FuadXLogger is not configured; entry dropped");
            return;
        }
        payload = (entry.asJsonOrdered().toString() + "\n").getBytes(StandardCharsets.UTF_8);
        try (FileOutputStream fos = new FileOutputStream(destination, true)) {
            fos.write(payload);
        }
        catch (IOException e) {
            Log.e(TAG, "Unable to save entry for FuadXLogger", e);
        }
    }
}
