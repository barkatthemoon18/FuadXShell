package com.fuad.fuadx.detection.frida;

import com.fuad.fuadx.detection.DetectionContext;
import com.fuad.fuadx.detection.DetectionEvidence;
import com.fuad.fuadx.detection.DetectionModule;
import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.DetectionSource;
import com.fuad.fuadx.frida.Frida;
import com.fuad.fuadx.frida.FridaLoadedLibraryProbe;
import com.fuad.fuadx.frida.FridaModuleInfo;
import com.fuad.fuadx.frida.FridaNamedPipeProbe;
import com.fuad.fuadx.frida.FridaThreadProbe;
import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Supplier;

public class FridaDetectionModule implements DetectionModule {
    private static final ExecutorService DEFAULT_EXECUTOR = Executors.newFixedThreadPool(3,
            runnable -> {
        Thread thread = new Thread(runnable, "FuadX-Frida-Probes");
        thread.setDaemon(true);
        return thread;
    });
    private final Supplier<HeuristicResult> threadProbe;
    private final Supplier<HeuristicResult> pipesProbe;
    private final Supplier<HeuristicResult> libraryProbe;
    private final Executor executor;

    public FridaDetectionModule() {
        this(new FridaThreadProbe()::scan, new FridaNamedPipeProbe()::scan,
                new FridaLoadedLibraryProbe()::scan, DEFAULT_EXECUTOR);
    }

    FridaDetectionModule(Supplier<HeuristicResult> threadProbe, Supplier<HeuristicResult> pipesProbe,
                         Supplier<HeuristicResult> libraryProbe, Executor executor) {
        this.threadProbe = Objects.requireNonNull(threadProbe);
        this.pipesProbe = Objects.requireNonNull(pipesProbe);
        this.libraryProbe = Objects.requireNonNull(libraryProbe);
        this.executor = Objects.requireNonNull(executor);
    }

    @Override
    public ModuleId id() {
        return ModuleId.FRIDA;
    }

    @Override
    public DetectionResult check(DetectionContext context) {
        Objects.requireNonNull(context, "context");

        try {
            CompletableFuture<HeuristicResult> threads = submit(threadProbe, "FRIDA_THREAD_PROBE_FAILED");
            CompletableFuture<HeuristicResult> pipes = submit(pipesProbe, "FRIDA_PIPE_PROBE_FAILED");
            CompletableFuture<HeuristicResult> libraries = submit(libraryProbe, "FRIDA_LIBRARY_PROBE_FAILED");
            CompletableFuture.allOf(threads, pipes, libraries).join();
            return FridaResultAggregator.aggregate(threads.join(), pipes.join(), libraries.join());
        }
        catch (RuntimeException e) {
            return DetectionResult.error(id(), "FRIDA_EXECUTION_ERROR",
                    "Unable to complete Frida evaluation: " + e.getClass().getSimpleName());
        }
    }

    private CompletableFuture<HeuristicResult> submit(Supplier<HeuristicResult> probe, String errorCode) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                HeuristicResult result = probe.get();
                if (result == null) {
                    return HeuristicResult.error(errorCode, "Probe returned null");
                }
                return result;
            }
            catch (RuntimeException e) {
                return HeuristicResult.error(errorCode, "Probe failed: " + e.getClass().getSimpleName());
            }
        }, executor);
    }
}
