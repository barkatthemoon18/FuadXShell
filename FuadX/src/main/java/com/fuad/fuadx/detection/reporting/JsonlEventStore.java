package com.fuad.fuadx.detection.reporting;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

public final class JsonlEventStore implements Consumer<Map<String, Object>> {
    private final Gson gson = new GsonBuilder().disableHtmlEscaping().create();
    private final File currentFile;
    private final File previousFile;
    private final long maxFileBytes;

    public JsonlEventStore(File directory, long maxFileBytes) {
        Objects.requireNonNull(directory, "directory");

        if (maxFileBytes <= 0) {
            throw new IllegalArgumentException("Maximum file size must be positive");
        }
        if (!directory.exists() && !directory.mkdirs()) {
            throw new IllegalStateException("Unable to create reporting directory");
        }
        if (!directory.isDirectory()) {
            throw new IllegalArgumentException("Reporte path is not a directory");
        }
        this.currentFile = new File(directory, "fuadx-events.jsonl");
        this.previousFile = new File(directory, "fuadx-events.1.jsonl");
        this.maxFileBytes = maxFileBytes;
    }

    @Override
    public void accept(Map<String, Object> event) {
        byte[] payload;

        Objects.requireNonNull(event, "event");
        payload = (gson.toJson(event) + "\n").getBytes(StandardCharsets.UTF_8);
        if (payload.length > maxFileBytes) {
            throw new IllegalArgumentException("Event exceeds maximum file size");
        }
        if (currentFile.exists() && currentFile.length() > maxFileBytes - payload.length) {
            rotate();
        }
        try (FileOutputStream fos = new FileOutputStream(currentFile, true)) {
            fos.write(payload);
        }
        catch (IOException e) {
            throw new UncheckedIOException("Unable to write detection event", e);
        }
    }

    private void rotate() {
        if (previousFile.exists() && !previousFile.delete()) {
            throw new IllegalStateException("Unable to remove previous event log");
        }
        if (currentFile.exists() && !currentFile.renameTo(previousFile)) {
            throw new IllegalStateException("Unable to rotate event log");
        }
    }
}
