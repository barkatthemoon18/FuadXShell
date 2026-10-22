package com.fuad.fuadx.detection.debug;

import com.fuad.fuadx.debug.DebugJdwpThreadProbe;
import com.fuad.fuadx.debug.DebugTracerPidProbe;
import com.fuad.fuadx.detection.DetectionContext;
import com.fuad.fuadx.detection.DetectionModule;
import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;

import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

public class DebugDetectionModule implements DetectionModule {
    private static final long DEFAULT_TIMEOUT_MILLIS = 3000L;
    private static final ExecutorService SHARED_EXECUTOR = new ThreadPoolExecutor(0, 3, 30,
            TimeUnit.SECONDS, new SynchronousQueue<>(), runnable -> {
        Thread thread = new Thread(runnable, "FuadX-Debug-Probe");
        thread.setDaemon(true);
        return thread;
    }, new ThreadPoolExecutor.AbortPolicy());
    private final DebugProbeRunner runner;

    public DebugDetectionModule() {
        this(new DebugTracerPidProbe()::scan, new DebugJdwpThreadProbe()::scan, SHARED_EXECUTOR,
                DEFAULT_TIMEOUT_MILLIS);
    }

    public DebugDetectionModule(Supplier<HeuristicResult> tracerPidProbe, Supplier<HeuristicResult> jdwpThreadsProbe,
                                ExecutorService executor, long timeoutMillis) {
        this.runner = new DebugProbeRunner(Objects.requireNonNull(tracerPidProbe, "tracerPidProbe"),
                Objects.requireNonNull(jdwpThreadsProbe, "jdwpThreadsProbe"), executor, timeoutMillis);
    }

    @Override
    public ModuleId id() {
        return ModuleId.DEBUG;
    }

    @Override
    public DetectionResult check(DetectionContext context) {
        Objects.requireNonNull(context, "context");

        return runner.execute();
    }
}
