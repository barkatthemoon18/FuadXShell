package com.fuad.fuadx.detection.debug;

import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.DetectionResultAggregator;
import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public class DebugResultAggregator {

    private DebugResultAggregator() {
        /* Empty intentionally */
    }

    public static DetectionResult aggregate(Map<String, HeuristicResult> results) {
        Map<String, HeuristicResult> ordered = new LinkedHashMap<>();

        Objects.requireNonNull(results, "results");
        if (results.size() != 2 || !results.containsKey("tracerPid") || !results.containsKey("jdwpThreads")) {
            throw new IllegalArgumentException("Unexpected Debug probe result set");
        }
        ordered.put("tracerPid", Objects.requireNonNull(results.get("tracerPid"), "tracerPid"));
        ordered.put("jdwpThreads", Objects.requireNonNull(results.get("jdwpThreads"), "jdwpThreads"));
        return DetectionResultAggregator.aggregate(ModuleId.DEBUG, ordered);
    }
}
