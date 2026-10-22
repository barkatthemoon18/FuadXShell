package com.fuad.fuadx.detection.frida;

import com.fuad.fuadx.detection.DetectionContext;
import com.fuad.fuadx.detection.DetectionModule;
import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.frida.FridaLoadedLibraryProbe;
import com.fuad.fuadx.frida.FridaNamedPipeProbe;
import com.fuad.fuadx.frida.FridaThreadProbe;
import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;

import java.util.Objects;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

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
        this(new FridaThreadProbe()::scan, new FridaNamedPipeProbe()::scan,
                new FridaLoadedLibraryProbe()::scan, SHARED_EXECUTOR, DEFAULT_TIMEOUT_MILLIS);
    }

    FridaDetectionModule(Supplier<HeuristicResult> threadProbe, Supplier<HeuristicResult> pipesProbe,
                         Supplier<HeuristicResult> libraryProbe, ExecutorService executor, long timeoutMillis) {
        this.runner = new FridaProbeRunner(Objects.requireNonNull(threadProbe, "threads"),
                Objects.requireNonNull(pipesProbe, "pipes"),
                Objects.requireNonNull(libraryProbe, "libraries"), executor, timeoutMillis);
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
}
