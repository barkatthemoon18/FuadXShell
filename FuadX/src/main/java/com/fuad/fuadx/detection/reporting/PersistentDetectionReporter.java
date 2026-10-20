package com.fuad.fuadx.detection.reporting;

import android.content.Context;
import android.util.Log;

import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.policy.DetectionDecision;

import java.io.File;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

public final class PersistentDetectionReporter implements DetectionReporter, AutoCloseable {
    private static final String TAG = "FuadXDetection";
    private static final int QUEUE_CAPACITY = 128;
    private static final long MAX_FILE_BYTES = 1024L * 1024L;
    private final LogcatDetectionReporter logcatReporter = new LogcatDetectionReporter();
    private final AsyncDetectionReporter asyncReporter;

    public PersistentDetectionReporter(Context context) {
        File directory;
        JsonlEventStore store;
        StructuredDetectionReporter structuredReporter;


        Objects.requireNonNull(context, "context");
        directory = new File(context.getNoBackupFilesDir(), "fuadx-detections");
        store = new JsonlEventStore(directory, MAX_FILE_BYTES);
        structuredReporter = new StructuredDetectionReporter(store);
        asyncReporter = new AsyncDetectionReporter(QUEUE_CAPACITY, structuredReporter,
                result -> Log.e(TAG, "Detection not persisted: module=" +
                        result.getModuleId() + ", status=" + result.getStatus()),
                error -> Log.e(TAG, "Persistent reporting failed", error));
    }

    @Override
    public void report(DetectionResult result, DetectionDecision decision) {
        Objects.requireNonNull(result, "result");
        Objects.requireNonNull(decision, "decision");

        asyncReporter.report(result, decision);
        logcatReporter.report(result, decision);
    }

    @Override
    public void close() {
        asyncReporter.close();
    }

    public long getDroppedDiagnostics() {
        return asyncReporter.getDroppedDiagnostics();
    }

    public long getUndeliveredDetections() {
        return asyncReporter.getUndeliveredDetections();
    }

    public long getDeliveryFailures() {
        return asyncReporter.getDeliveryFailures();
    }

    public int getPendingEvents() {
        return asyncReporter.getPendingEvents();
    }

    public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
        return asyncReporter.awaitTermination(timeout, unit);
    }
}
