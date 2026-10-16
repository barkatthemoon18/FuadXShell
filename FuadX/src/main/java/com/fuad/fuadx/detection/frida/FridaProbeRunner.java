package com.fuad.fuadx.detection.frida;

import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

public final class FridaProbeRunner {
    private static final String[] ERROR_CODES = {
            "FRIDA_THREAD_PROBE_FAILED",
            "FRIDA_PIPES_PROBE_FAILED",
            "FRIDA_LIBRARY_PROBE_FAILED"
    };
    private final ExecutorService executor;
    private final AtomicBoolean evaluating = new AtomicBoolean();
    private final long timeoutMillis;

    FridaProbeRunner(ExecutorService executor, long timeoutMillis) {
        this.executor = Objects.requireNonNull(executor);

        if (timeoutMillis <= 0 || timeoutMillis >= 60_000) {
            throw new IllegalArgumentException("Timeout must be between 1 and 60 seconds");
        }
        this.timeoutMillis = timeoutMillis;
    }

    DetectionResult execute(Supplier<HeuristicResult> threads, Supplier<HeuristicResult> pipes,
                            Supplier<HeuristicResult> libraries) {
        List<Future<HeuristicResult>> futures = new ArrayList<>(3);
        List<Supplier<HeuristicResult>> suppliers = Arrays.asList(Objects.requireNonNull(threads),
                Objects.requireNonNull(pipes), Objects.requireNonNull(libraries));
        HeuristicResult[] results = new HeuristicResult[3];
        Future<HeuristicResult> future;
        boolean interrupted = false;
        long deadline;
        long remaining;

        if (!evaluating.compareAndSet(false, true)) {
            return DetectionResult.error(ModuleId.FRIDA, "FRIDA_EVALUATION_BUSY",
                    "Another Frida evaluation is already running");
        }
        try {
            deadline = System.nanoTime() + TimeUnit.MICROSECONDS.toNanos(timeoutMillis);
            for (int i = 0; i < 3; i++) {
                futures.add(null);
            }
            for (int i = 0; i < suppliers.size(); i++) {
                final int index = i;
                Supplier<HeuristicResult> probe = suppliers.get(i);
                try {
                    futures.set(i, executor.submit(() -> {
                        try {
                            HeuristicResult result = probe.get();
                            return result != null ? result : HeuristicResult.error(ERROR_CODES[index], "Probe returned null");
                        }
                        catch (RuntimeException e) {
                            return HeuristicResult.error(ERROR_CODES[index], "Probe failed: " + e.getClass().getSimpleName());
                        }
                    }));
                }
                catch (RejectedExecutionException e) {
                    results[i] = HeuristicResult.error("FRIDA_EXECUTOR_SATURATED",
                            "Executor rejected " + ERROR_CODES[i]);
                }
            }
            for (int i = 0; i < futures.size(); i++) {
                future = futures.get(i);
                if (future == null || results[i] != null) {
                    continue;
                }
                remaining = deadline - System.nanoTime();
                if (remaining <= 0) {
                    break;
                }
                try {
                    results[i] = future.get(remaining, TimeUnit.NANOSECONDS);
                }
                catch (TimeoutException e) {
                    break;
                }
                catch (InterruptedException e) {
                    interrupted = true;
                    break;
                }
                catch (ExecutionException | CancellationException e) {
                    results[i] = unexpectedFailure(i);
                }
            }
            for (int i = 0; i < futures.size(); i++) {
                future = futures.get(i);
                if (results[i] != null || future == null || !future.isDone()) {
                    continue;
                }
                try {
                    results[i] = future.get();
                }
                catch (InterruptedException e) {
                    interrupted = true;
                }
                catch (ExecutionException | CancellationException e) {
                    results[i] = unexpectedFailure(i);
                }
            }
            for (int i = 0; i < results.length; i++) {
                if (results[i] != null) {
                    continue;
                }
                results[i] = interrupted ? HeuristicResult.error("FRIDA_EVALUATION_INTERRUPTED", "Evaluation was interrupted") : HeuristicResult.inconclusive("Probe exceeded evaluation deadline");
            }
            return FridaResultAggregator.aggregate(results[0], results[1], results[2]);
        }
        finally {
            for (Future<HeuristicResult> futureInside : futures) {
                if (futureInside != null && !futureInside.isDone()) {
                    futureInside.cancel(true);
                }
            }
            evaluating.set(false);
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private static HeuristicResult unexpectedFailure(int index) {
        return HeuristicResult.error(ERROR_CODES[index], "Probe terminated unexpectedly");
    }
}
