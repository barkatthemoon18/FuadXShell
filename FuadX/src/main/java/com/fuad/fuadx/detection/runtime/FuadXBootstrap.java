package com.fuad.fuadx.detection.runtime;

import android.content.Context;
import android.util.Log;

import com.fuad.fuadx.detection.debug.DebugDetectionModule;
import com.fuad.fuadx.detection.frida.FridaDetectionModule;
import com.fuad.fuadx.detection.policy.MonitoringDetectionPolicy;
import com.fuad.fuadx.detection.reporting.PersistentDetectionReporter;
import com.fuad.fuadx.module.ModuleId;

import java.util.Arrays;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

public final class FuadXBootstrap implements AutoCloseable {
    private static final String TAG = "FuadXBootstrap";
    private static final long FRIDA_INTERVAL_MILLIS = 5000L;
    private static final long DEBUG_INTERVAL_MILLIS = 5000L;

    public enum State {
        NEW,
        STARTING,
        RUNNING,
        FAILED,
        SKIPPED,
        CLOSED
    }

    private final Context context;
    private final AtomicReference<State> state = new AtomicReference<>(State.NEW);
    private FuadXRuntime runtime;
    private PersistentDetectionReporter reporter;

    public FuadXBootstrap(Context context) {
        this.context = Objects.requireNonNull(context, "context");
    }

    @Override
    public synchronized void close() {
        if (state.get() == State.CLOSED) {
            return;
        }
        state.set(State.CLOSED);
        if (runtime != null) {
            runtime.close();
            runtime = null;
        }
        if (reporter != null) {
            reporter.close();
            reporter = null;
        }
    }

    public void start() {
        Thread worker;

        if (!state.compareAndSet(State.NEW, State.STARTING)) {
            return;
        }
        worker = new Thread(this::initialize, "FuadX-Bootstrap");
        worker.setDaemon(true);
        worker.start();
    }

    public State getState() {
        return state.get();
    }

    private void initialize() {
        PersistentDetectionReporter newReporter = null;
        FuadXRuntime newRuntime = null;
        boolean fridaStarted;
        boolean debugStarted;

        try {
            if (state.get() != State.STARTING) {
                return;
            }
            newReporter = new PersistentDetectionReporter(context);
            newRuntime = new FuadXRuntime(context, result -> Log.i(TAG, "module=" +
                    result.getModuleId() + ", status=" + result.getStatus() + ", evidence="
                    + result.getEvidence().size() + ", diagnostics=" + result.getDiagnostics().size()),
                    new MonitoringDetectionPolicy(), newReporter,
                    Arrays.asList(new FridaDetectionModule(), new DebugDetectionModule()));
            fridaStarted = newRuntime.start(ModuleId.FRIDA, FRIDA_INTERVAL_MILLIS);
            debugStarted = newRuntime.start(ModuleId.DEBUG, DEBUG_INTERVAL_MILLIS);
            if (!fridaStarted || !debugStarted) {
                throw new IllegalStateException("Unable to schedule Frida and Debug modules");
            }
            synchronized (this) {
                if (state.get() != State.STARTING) {
                    return;
                }
                reporter = newReporter;
                runtime = newRuntime;
                state.set(State.RUNNING);
            }
            Log.i(TAG, "FuadXRuntime initialized");
        }
        catch (RuntimeException e) {
            if (state.compareAndSet(State.STARTING, State.FAILED)) {
                Log.e(TAG, "FuadX initialization failed", e);
            }
        }
        finally {
            if (state.get() != State.RUNNING) {
                if (newRuntime != null) {
                    newRuntime.close();
                }
                if (newReporter != null) {
                    newReporter.close();
                }
            }
        }
    }
}
