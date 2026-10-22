package com.fuad.fuadx.detection;

import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class DetectionResultAggregator {
    private DetectionResultAggregator() {
        /* Empty intentionally */
    }

    public static DetectionResult aggregate(ModuleId moduleId, Map<String, HeuristicResult> probes) {
        List<DetectionEvidence> evidences = new ArrayList<>();
        List<DetectionDiagnostic> diagnostics = new ArrayList<>();
        List<String> reasons = new ArrayList<>();
        HeuristicResult result;
        String firstErrorCode = null;
        String name;
        boolean inconclusive = false;

        Objects.requireNonNull(moduleId, "moduleId");
        Objects.requireNonNull(probes, "probes");

        if (probes.isEmpty()) {
            throw new IllegalArgumentException("At least one probe must be provided");
        }
        for (Map.Entry<String, HeuristicResult> entry : probes.entrySet()) {
            name = Objects.requireNonNull(entry.getKey(), "probe name");
            if (name.trim().isEmpty()) {
                throw new IllegalArgumentException("Probe name cannot be blank");
            }
            result = Objects.requireNonNull(entry.getValue(), "probe result: " + name);
            switch (result.getStatus()) {
                case DETECTED:
                    evidences.addAll(result.getEvidence());
                    break;
                case ERROR:
                    if (firstErrorCode == null) {
                        firstErrorCode = result.getErrorCode();
                    }
                    diagnostics.add(DetectionDiagnostic.error(name, result.getReason(), result.getErrorCode()));
                    reasons.add(name + ": " + result.getReason());
                    break;
                case INCONCLUSIVE:
                    inconclusive = true;
                    diagnostics.add(DetectionDiagnostic.inconclusive(name, result.getReason()));
                    reasons.add(name + ": " + result.getReason());
                    break;
                case NO_DETECTION:
                    break;
            }
        }
        if (!evidences.isEmpty()) {
            return DetectionResult.detected(moduleId, evidences, diagnostics);
        }
        if (firstErrorCode != null) {
            return DetectionResult.error(moduleId, firstErrorCode, String.join("; ", reasons), diagnostics);
        }
        if (inconclusive) {
            return DetectionResult.inconclusive(moduleId, String.join("; ", reasons), diagnostics);
        }
        return DetectionResult.clean(moduleId);
    }
}
