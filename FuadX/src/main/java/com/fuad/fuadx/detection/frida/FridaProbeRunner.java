package com.fuad.fuadx.detection.frida;

import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;
import com.fuad.fuadx.probe.AbstractProbeRunner;
import com.fuad.fuadx.probe.ProbeDefinition;

import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.function.Supplier;

public final class FridaProbeRunner extends AbstractProbeRunner {

    FridaProbeRunner(Supplier<HeuristicResult> threads, Supplier<HeuristicResult> pipes,
                     Supplier<HeuristicResult> libraries, ExecutorService executor, long timeoutMillis) {
        super(ModuleId.FRIDA, Arrays.asList(
                new ProbeDefinition("threads", "FRIDA_THREAD_PROBE_FAILED", threads),
                new ProbeDefinition("pipes", "FRIDA_PIPE_PROBE_FAILED", pipes),
                new ProbeDefinition("libraries", "FRIDA_LIBRARY_PROBE_FAILED", libraries)),
                executor, timeoutMillis, FridaResultAggregator::aggregate);
    }

    @Override
    public HeuristicResult unexpectedFailure(ProbeDefinition probe, RuntimeException failure) {
        return HeuristicResult.error(probe.getErrorCode(), "Probe failed: " + failure.getClass().getSimpleName());
    }
}
