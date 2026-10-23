package com.fuad.fuadx.detection.debug;

import com.fuad.fuadx.debug.DebugJavaDebuggerProbe;
import com.fuad.fuadx.debug.DebugJdwpThreadProbe;
import com.fuad.fuadx.debug.DebugThreadTracerPidProbe;
import com.fuad.fuadx.debug.DebugTracedStateProbe;
import com.fuad.fuadx.debug.DebugTracerPidProbe;
import com.fuad.fuadx.debug.DebugWchanProbe;
import com.fuad.fuadx.detection.DetectionContext;
import com.fuad.fuadx.detection.DetectionModule;
import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.module.ModuleId;
import com.fuad.fuadx.probe.ProbeDefinition;

import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

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
         this(defaultProbes(), SHARED_EXECUTOR, DEFAULT_TIMEOUT_MILLIS);
    }

    DebugDetectionModule(List<ProbeDefinition> probes, ExecutorService executor, long timeoutMillis) {
        this.runner = new DebugProbeRunner(Objects.requireNonNull(probes), executor, timeoutMillis);
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

    private static List<ProbeDefinition> defaultProbes() {
        return List.of(
                new ProbeDefinition("tracerPid", "DEBUG_TRACERPID_PROBE_FAILED",
                        new DebugTracerPidProbe()::scan),
                new ProbeDefinition("jdwpThreads", "DEBUG_JDWP_THREADS_PROBE_FAILED",
                        new DebugJdwpThreadProbe()::scan),
                new ProbeDefinition("threadTracerPid", "DEBUG_THREAD_TRACERPID_PROBE_FAILED",
                        new DebugThreadTracerPidProbe()::scan),
                new ProbeDefinition("tracedState", "DEBUG_TRACED_STATE_PROBE_FAILED",
                        new DebugTracedStateProbe()::scan),
                new ProbeDefinition("wchan", "DEBUG_WCHAN_PROBE_FAILED",
                        new DebugWchanProbe()::scan),
                new ProbeDefinition("javaDebugger", "DEBUG_JAVA_DEBUGGER_PROBE_FAILED",
                        new DebugJavaDebuggerProbe()::scan));
    }
}
