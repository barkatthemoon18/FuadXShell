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
        String probe;
        boolean inconclusive = false;

        Objects.requireNonNull(moduleId, "moduleId");
        Objects.requireNonNull(probes, "probes");
        for (Map.Entry<String, HeuristicResult> entry : probes.entrySet()) {
            probe = Objects.requireNonNull(entry.getKey(), "probe");
            if (probe.trim().isEmpty()) {
                throw new IllegalArgumentException("Probe name cannot be blank");
            }
            result = Objects.requireNonNull(entry.getValue(), "Probe result cannot be null: " + probe);
            switch (result.getStatus()) {
                case DETECTED:
                    evidences.addAll(result.getEvidence());
                    break;
                case ERROR:
                    if (firstErrorCode == null) {
                        firstErrorCode = result.getErrorCode();
                    }
                    diagnostics.add(DetectionDiagnostic.error(probe, result.getReason(), result.getErrorCode()));
                    reasons.add(probe + ": " + result.getReason());
                    break;
                case INCONCLUSIVE:
                    inconclusive = true;
                    diagnostics.add(DetectionDiagnostic.inconclusive(probe, result.getReason()));
                    reasons.add(probe + ": " + result.getReason());
                    break;
                case NO_DETECTION:
                    break;
                default:
                    throw new IllegalStateException("Unsupported heuristic status");
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
