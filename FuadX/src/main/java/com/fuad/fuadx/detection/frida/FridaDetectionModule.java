package com.fuad.fuadx.detection.frida;

import com.fuad.fuadx.detection.DetectionContext;
import com.fuad.fuadx.detection.DetectionModule;
import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.frida.FridaLoadedLibraryProbe;
import com.fuad.fuadx.frida.FridaNamedPipeProbe;
import com.fuad.fuadx.frida.FridaThreadProbe;
import com.fuad.fuadx.module.ModuleId;
import com.fuad.fuadx.probe.ProbeDefinition;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class FridaDetectionModule implements DetectionModule {
    private static final long DEFAULT_TIMEOUT_MILLIS = 3000L;
    private static final ExecutorService SHARED_EXECUTOR = new ThreadPoolExecutor(0, 3, 30,
            TimeUnit.SECONDS, new SynchronousQueue<>(), runnable -> {
        Thread thread = new Thread(runnable, "FuadX-Frida-Probe");
        thread.setDaemon(true);
        return thread;
    }, new ThreadPoolExecutor.AbortPolicy());
    private final FridaProbeRunner runner;

    public FridaDetectionModule() {
        this(defaultProbes(), SHARED_EXECUTOR, DEFAULT_TIMEOUT_MILLIS);
    }

    FridaDetectionModule(List<ProbeDefinition> probes, ExecutorService executor, long timeoutMillis) {
        this.runner = new FridaProbeRunner(Objects.requireNonNull(probes), executor, timeoutMillis);
    }

    @Override
    public ModuleId id() {
        return ModuleId.FRIDA;
    }

    @Override
    public DetectionResult check(DetectionContext context) {
        Objects.requireNonNull(context, "context");

        return runner.execute();
    }

    private static List<ProbeDefinition> defaultProbes() {
        return Arrays.asList(
                new ProbeDefinition("threads", "FRIDA_THREAD_PROBE_FAILED",
                        new FridaThreadProbe()::scan),
                new ProbeDefinition("pipes", "FRIDA_PIPE_PROBE_FAILED",
                        new FridaNamedPipeProbe()::scan),
                new ProbeDefinition("libraries", "FRIDA_LIBRARY_PROBE_FAILED",
                        new FridaLoadedLibraryProbe()::scan));
    }
}
