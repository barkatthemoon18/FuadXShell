package com.fuad.fuadx.detection.frida;

import com.fuad.fuadx.detection.DetectionDiagnostic;
import com.fuad.fuadx.detection.DetectionEvidence;
import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.DetectionResultAggregator;
import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class FridaResultAggregator {

    private FridaResultAggregator() {
        /* Empty intentionally */
    }

    public static DetectionResult aggregate(HeuristicResult threads, HeuristicResult pipes,
                                            HeuristicResult libraries) {
        Map<String, HeuristicResult> results = new LinkedHashMap<>();

        results.put("threads", Objects.requireNonNull(threads, "threads"));
        results.put("pipes", Objects.requireNonNull(pipes, "pipes"));
        results.put("libraries", Objects.requireNonNull(libraries, "libraries"));
        return DetectionResultAggregator.aggregate(ModuleId.FRIDA, results);
    }
}
