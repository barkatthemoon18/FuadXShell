package com.fuad.fuadx.detection.debug;

import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.DetectionResultAggregator;
import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;

import java.util.LinkedHashMap;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class DebugResultAggregator {
    private static final List<String> PROBES = Collections.unmodifiableList(Arrays.asList(
            "tracerPid", "jdwpThreads", "threadTracerPid",
            "tracedState", "wchan", "javaDebugger"));

    private DebugResultAggregator() {
        /* Empty intentionally */
    }

    public static DetectionResult aggregate(Map<String, HeuristicResult> results) {
        Map<String, HeuristicResult> ordered = new LinkedHashMap<>();

        Objects.requireNonNull(results, "results");
        if (!(results.size() == PROBES.size() && results.keySet().containsAll(PROBES))) {
            throw new IllegalArgumentException("Unexpected Debug probe result set");
        }
        for (String name : PROBES) {
            if (!results.containsKey(name)) {
                continue;
            }
            ordered.put(name, Objects.requireNonNull(results.get(name), name));
        }
        return DetectionResultAggregator.aggregate(ModuleId.DEBUG, ordered);
    }
}
