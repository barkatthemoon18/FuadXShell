package com.fuad.fuadx.probe;

import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;

public abstract class AbstractProbeRunner implements ProbeRunner {
    private final ModuleId moduleId;
    private final List<ProbeDefinition> probes;
    private final ExecutorService executor;
    private final long timeoutMillis;
    private final Function<Map<String, HeuristicResult>, DetectionResult> aggregator;
    private final AtomicBoolean evaluating = new AtomicBoolean(false);

    protected AbstractProbeRunner(ModuleId moduleId, List<ProbeDefinition> probes,
                                  ExecutorService executor, long timeoutMillis,
                                  Function<Map<String, HeuristicResult>, DetectionResult> aggregator) {
        List<ProbeDefinition> copy;
        ProbeDefinition checked;
        Set<String> names = new HashSet<>();

        Objects.requireNonNull(probes);
        this.moduleId = Objects.requireNonNull(moduleId);
        this.executor = Objects.requireNonNull(executor);
        this.timeoutMillis = timeoutMillis;
        this.aggregator = Objects.requireNonNull(aggregator);

        if (timeoutMillis <= 0 || timeoutMillis >= 60_000) {
            throw new IllegalArgumentException("Timeout must be between 1 and 59999 ms");
        }
        if (probes.isEmpty()) {
            throw new IllegalArgumentException("At least one probe must be provided");
        }
        copy = new ArrayList<>(probes);
        for (ProbeDefinition probe : probes) {
            checked = Objects.requireNonNull(probe, "probe");
            if (!names.add(checked.getName())) {
                throw new IllegalArgumentException("Duplicate probe name: " + checked.getName());
            }
            copy.add(checked);
        }
        this.probes = Collections.unmodifiableList(copy);
    }

    @Override
    public final DetectionResult execute() {
        List<Future<HeuristicResult>> futures = new ArrayList<>(probes.size());
        HeuristicResult[] results = new HeuristicResult[probes.size()];
        Map<String, HeuristicResult> evaluated = new LinkedHashMap<>();
        boolean interrupted = false;
        Future<HeuristicResult> future;
        HeuristicResult value;
        DetectionResult outcome;
        long deadlineNanos;
        long remaining;

        if (!evaluating.compareAndSet(false, true)) {
            return DetectionResult.error(moduleId, moduleId.name() + "_EVALUATION_BUSY",
                    "Another evaluation is already running");
        }
        try {
            deadlineNanos = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
            for (int i = 0; i < probes.size(); i++) {
                ProbeDefinition probe = probes.get(i);
                try {
                    futures.add(executor.submit(() -> runSafely(probe)));
                }
                catch (RejectedExecutionException e) {
                    futures.add(null);
                    results[i] = HeuristicResult.error(moduleId.name() + "_EXECUTOR_SATURATED",
                            "Executor rejected " + probe.getErrorCode());
                }
            }
            for (int i = 0; i < futures.size(); i++) {
                future = futures.get(i);
                if (future == null || results[i] != null) {
                    continue;
                }
                remaining = deadlineNanos - System.nanoTime();
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
                    results[i] = completedWithFailure(probes.get(i), e);
                }
            }
            if (!interrupted) {
                for (int i = 0; i < futures.size(); i++) {
                    future = futures.get(i);
                    if (future == null || results[i] != null || !future.isDone()) {
                        continue;
                    }
                    try {
                        results[i] = future.get();
                    }
                    catch (InterruptedException e) {
                        interrupted = true;
                        break;
                    }
                    catch (ExecutionException | CancellationException e) {
                        results[i] = completedWithFailure(probes.get(i), e);
                    }
                }
            }
            for (int i = 0; i < probes.size(); i++) {
                value = results[i];
                if (value == null) {
                    value = interrupted ? HeuristicResult.error(moduleId.name() + "_EVALUATION_INTERRUPTED",
                            "Evaluation was interrupted") : HeuristicResult.inconclusive("Probe exceeded evaluation deadline");
                }
                evaluated.put(probes.get(i).getName(), value);
            }
            outcome = Objects.requireNonNull(aggregator.apply(Collections.unmodifiableMap(evaluated)), "Aggregator returned null");
            if (outcome.getModuleId() != moduleId) {
                throw new IllegalStateException("Aggregator returned unexpected module ID");
            }
            return outcome;
        }
        finally {
            for (Future<HeuristicResult> futureLoop : futures) {
                if (futureLoop != null && !futureLoop.isDone()) {
                    futureLoop.cancel(true);
                }
            }
            evaluating.set(false);
            if (interrupted) {
                Thread.currentThread().interrupt();
            }
        }
    }

    private HeuristicResult runSafely(ProbeDefinition probe) {
        HeuristicResult result;

        try {
            result = probe.getHeuristic().get();
            return result != null ? result : HeuristicResult.error(probe.getErrorCode(), "Probe returned null");
        }
        catch (RuntimeException e) {
            return recover(probe, e);
        }
    }

    private HeuristicResult completedWithFailure(ProbeDefinition probe, Exception e) {
        Throwable cause = e instanceof  ExecutionException && e.getCause() != null ? e.getCause() : e;
        RuntimeException failure = cause instanceof RuntimeException ? (RuntimeException) cause :
                new IllegalStateException("Probe terminated unexpectedly", cause);

        return recover(probe, failure);
    }

    private HeuristicResult recover(ProbeDefinition probe, RuntimeException failure) {
        HeuristicResult result;

        try {
            result = unexpectedFailure(probe, failure);
            if (result != null) {
                return result;
            }
            return HeuristicResult.error(probe.getErrorCode(), "Failure handler returned null");
        }
        catch (RuntimeException e) {
            return HeuristicResult.error(probe.getErrorCode(), "Failure handled failed: " + e.getClass().getSimpleName());
        }
    }
}
