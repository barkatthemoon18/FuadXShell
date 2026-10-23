package com.fuad.fuadx.detection.debug;

import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;
import com.fuad.fuadx.probe.AbstractProbeRunner;
import com.fuad.fuadx.probe.ProbeDefinition;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.function.Supplier;

public final class DebugProbeRunner extends AbstractProbeRunner {


    DebugProbeRunner(List<ProbeDefinition> probes, ExecutorService executor, long timeoutMillis) {
        super(ModuleId.DEBUG, probes, executor, timeoutMillis, DebugResultAggregator::aggregate);
    }

    DebugProbeRunner(Supplier<HeuristicResult> tracerPid, Supplier<HeuristicResult> jdwpThreads,
                     ExecutorService executor, long timeoutMillis) {
        super(ModuleId.DEBUG, Arrays.asList(
                new ProbeDefinition("tracerPid", "DEBUG_TRACERPID_PROBE_FAILED", tracerPid),
                new ProbeDefinition("jdwpThreads", "DEBUG_JDWP_THREADS_PROBE_FAILED", jdwpThreads)),
                executor, timeoutMillis, DebugResultAggregator::aggregate);
    }

    @Override
    public HeuristicResult unexpectedFailure(ProbeDefinition probe, RuntimeException failure) {
        return HeuristicResult.error(probe.getErrorCode(), "Probe failed: " + failure.getClass().getSimpleName());
    }
}
