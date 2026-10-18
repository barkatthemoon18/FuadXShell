package com.fuad.fuadx.detection.runtime;

import android.content.Context;
import android.util.Log;

import com.fuad.fuadx.detection.DetectionContext;
import com.fuad.fuadx.detection.DetectionModule;
import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.frida.FridaDetectionModule;
import com.fuad.fuadx.detection.policy.DetectionPolicy;
import com.fuad.fuadx.detection.policy.MonitoringDetectionPolicy;
import com.fuad.fuadx.detection.reporting.DetectionReporter;
import com.fuad.fuadx.detection.reporting.LogcatDetectionReporter;
import com.fuad.fuadx.module.ModuleId;

import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

public final class FuadXRuntime implements AutoCloseable {
    private static final String TAG = "FuadXRuntime";
    private final DetectionContext context;
    private final DetectionScheduler scheduler;
    private final Map<ModuleId, DetectionModule> modules = new EnumMap<>(ModuleId.class);
    private boolean closed;

    public FuadXRuntime(Context applicationContext, Consumer<DetectionResult> observer) {
        this(applicationContext, observer, new MonitoringDetectionPolicy(), new LogcatDetectionReporter());
    }

    public FuadXRuntime(Context applicationContext, Consumer<DetectionResult> observer,
                        DetectionPolicy policy, DetectionReporter reporter) {
        Consumer<DetectionResult> monitoringObserver;
        DetectionDispatcher dispacher;

        this.context = new DetectionContext(Objects.requireNonNull(applicationContext, "applicationContext"));
        monitoringObserver = Objects.requireNonNull(observer);
        dispacher = new DetectionDispatcher(Objects.requireNonNull(policy), Objects.requireNonNull(reporter));
        this.scheduler = new DetectionScheduler(result -> {
            try {
                dispacher.accept(result);
            }
            catch (RuntimeException e) {
                Log.e(TAG, "Detection dispatch failed", e);
            }
            try {
                monitoringObserver.accept(result);
            }
            catch (RuntimeException e) {
                Log.e(TAG, "Monitoring observer failed", e);
            }
        });
        register(new FridaDetectionModule());;
    }

    public synchronized boolean start(ModuleId moduleId, long intervalMillis) {
        DetectionModule module;

        ensureOpen();
        module = modules.get(Objects.requireNonNull(moduleId, "moduleId"));
        if (module == null) {
            throw new IllegalArgumentException("Module not registered: " + moduleId);
        }
        return scheduler.schedule(module, context, intervalMillis);
    }

    public synchronized boolean stop(ModuleId moduleId) {
        Objects.requireNonNull(moduleId, "moduleId");
        if (closed) {
            return false;
        }
        return scheduler.stop(moduleId);
    }

    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        scheduler.close();
    }

    private void register(DetectionModule module) {
        DetectionModule previous;

        Objects.requireNonNull(module, "module");
        previous = modules.putIfAbsent(module.id(), module);
        if (previous != null) {
            throw new IllegalStateException("Module already registered: " + module.id());
        }
    }

    private void ensureOpen() {
        if (closed) {
            throw new IllegalStateException("FuadXRuntime is closed");
        }
    }
}
