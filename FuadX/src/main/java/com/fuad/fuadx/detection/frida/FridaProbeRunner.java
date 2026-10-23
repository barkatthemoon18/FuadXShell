package com.fuad.fuadx.detection.frida;

import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;
import com.fuad.fuadx.probe.AbstractProbeRunner;
import com.fuad.fuadx.probe.ProbeDefinition;

import java.util.List;
import java.util.concurrent.ExecutorService;

public final class FridaProbeRunner extends AbstractProbeRunner {

    FridaProbeRunner(List<ProbeDefinition> probes, ExecutorService executor, long timeoutMillis) {
        super(ModuleId.FRIDA, probes, executor, timeoutMillis, FridaResultAggregator::aggregate);
    }

    @Override
    public HeuristicResult unexpectedFailure(ProbeDefinition probe, RuntimeException failure) {
        return HeuristicResult.error(probe.getErrorCode(), "Probe failed: " + failure.getClass().getSimpleName());
    }
}
