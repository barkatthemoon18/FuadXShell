package com.fuad.fuadx.detection.runtime;

import com.fuad.fuadx.detection.DetectionContext;
import com.fuad.fuadx.detection.DetectionModule;
import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.module.ModuleId;

import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class DetectionScheduler implements AutoCloseable {
    private static final Logger LOGGER = Logger.getLogger(DetectionScheduler.class.getName());
    private final ScheduledThreadPoolExecutor executor;
    private final Map<ModuleId, Registration> registrations = new EnumMap<>(ModuleId.class);
    private final Consumer<DetectionResult> observer;
    private boolean closed;

    private static final class Registration {
        final AtomicBoolean active = new AtomicBoolean(true);
        ScheduledFuture<?> future;
    }

    public DetectionScheduler(Consumer<DetectionResult> observer) {
        this.observer = Objects.requireNonNull(observer);
        executor = new ScheduledThreadPoolExecutor(1, runnable -> {
            Thread thread = new Thread(runnable, "FuadX-Detection-Scheduler");
            thread.setDaemon(true);
            return thread;
        });
        executor.setRemoveOnCancelPolicy(true);
    }

    public boolean schedule(DetectionModule module, DetectionContext context, long intervalMillis) {
        Objects.requireNonNull(module, "module");
        Objects.requireNonNull(context, "context");
        return schedule(module.id(), () -> module.check(context), intervalMillis);
    }

    synchronized boolean schedule(ModuleId moduleId, Supplier<DetectionResult> evaluation, long intervalMillis) {
        Registration registration = new Registration();

        Objects.requireNonNull(moduleId, "id");
        Objects.requireNonNull(evaluation, "evaluation");
        if (closed) {
            throw new IllegalStateException("Scheduler is closed");
        }
        if (intervalMillis <= 0) {
            throw new IllegalArgumentException("Interval must be positive");
        }
        if (registrations.containsKey(moduleId)) {
            return false;
        }
        registrations.put(moduleId, registration);
        registration.future = executor.scheduleWithFixedDelay(() ->
                execute(moduleId, evaluation, registration), 0, intervalMillis, TimeUnit.MILLISECONDS);
        return true;
    }

    private void execute(ModuleId moduleId, Supplier<DetectionResult> evaluation, Registration registration) {
        DetectionResult result;

        if (!registration.active.get()) {
            return;
        }
        try {
            result = Objects.requireNonNull(evaluation.get(), "Detection module returned null");
            if (result.getModuleId() != moduleId) {
                throw new IllegalStateException("Detection module returned result with unexpected module ID");
            }
        }
        catch (RuntimeException e) {
            result = DetectionResult.error(moduleId, "MODULE_EXECUTION_FAILED",
                    "Module execution failed: " + e.getClass().getSimpleName());
        }
        if (!registration.active.get()) {
            return;
        }
        try {
            observer.accept(result);
        }
        catch (RuntimeException e) {
            LOGGER.log(Level.WARNING, "Detection observer failed for " + moduleId, e);
        }
    }

    public synchronized boolean stop(ModuleId moduleId) {
        Registration registration;

        Objects.requireNonNull(moduleId, "moduleId");
        registration = registrations.remove(moduleId);
        if (registration == null) {
            return false;
        }
        registration.active.set(false);
        registration.future.cancel(false);
        return true;
    }

    @Override
    public synchronized void close() throws Exception {
        if (closed) {
            return;
        }
        closed = true;
        for (Registration registration : registrations.values()) {
            registration.active.set(false);
            registration.future.cancel(false);
        }
        registrations.clear();
        executor.shutdown();
    }
}
