package com.fuad.fuadx.detection.frida;

import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.DetectionResultAggregator;
import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public final class FridaResultAggregator {

    private FridaResultAggregator() {
        /* Empty intentionally */
    }

    public static DetectionResult aggregate(Map<String, HeuristicResult> results) {
        Map<String, HeuristicResult> ordered = new LinkedHashMap<>();

        Objects.requireNonNull(results, "results");
        if (results.size() != 3 || !results.containsKey("threads") || !results.containsKey("pipes") ||
                !results.containsKey("libraries")) {
            throw new IllegalArgumentException("Unexpected Frida probe result set");
        }
        ordered.put("threads", Objects.requireNonNull(results.get("threads"), "threads"));
        ordered.put("pipes", Objects.requireNonNull(results.get("pipes"), "pipes"));
        ordered.put("libraries", Objects.requireNonNull(results.get("libraries"), "libraries"));
        return DetectionResultAggregator.aggregate(ModuleId.FRIDA, ordered);
    }
}
