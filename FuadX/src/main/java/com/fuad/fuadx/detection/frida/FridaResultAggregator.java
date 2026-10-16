package com.fuad.fuadx.detection.frida;

import com.fuad.fuadx.detection.DetectionDiagnostic;
import com.fuad.fuadx.detection.DetectionEvidence;
import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class FridaResultAggregator {

    private FridaResultAggregator() {
        /* Empty intentionally */
    }

    public static DetectionResult aggregate(HeuristicResult threads, HeuristicResult pipes,
                                            HeuristicResult libraries) {
        HeuristicResult[] results = {
                Objects.requireNonNull(threads, "threads"),
                Objects.requireNonNull(pipes, "pipes"),
                Objects.requireNonNull(libraries, "libraries")
        };
        String[] names = { "threads", "pipes", "libraries" };
        List<DetectionEvidence> evidences = new ArrayList<>();
        List<DetectionDiagnostic> diagnostics = new ArrayList<>();
        List<String> reasons = new ArrayList<>();
        String firstErrorCode = null;
        boolean inconclusive = false;
        HeuristicResult result;

        for (int i = 0; i < results.length; i++) {
            result = results[i];
            switch (result.getStatus()) {
                case DETECTED:
                    evidences.addAll(result.getEvidence());
                    break;
                case ERROR:
                    if (firstErrorCode == null) {
                        firstErrorCode = result.getErrorCode();
                    }
                    diagnostics.add(DetectionDiagnostic.error(names[i], result.getReason(), result.getErrorCode()));
                    reasons.add(names[i] + ": " + result.getReason());
                    break;
                case INCONCLUSIVE:
                    inconclusive = true;
                    diagnostics.add(DetectionDiagnostic.inconclusive(names[i], result.getReason()));
                    reasons.add(names[i] + ": " + result.getReason());
                    break;
                case NO_DETECTION:
                    break;
                default:
                    throw new IllegalStateException("Unexpected heuristic status");
            }
        }
        if (!evidences.isEmpty()) {
            return DetectionResult.detected(ModuleId.FRIDA, evidences, diagnostics);
        }
        if (firstErrorCode != null) {
            return DetectionResult.error(ModuleId.FRIDA, firstErrorCode, String.join("; ", reasons),
                    diagnostics);
        }
        if (inconclusive) {
            return DetectionResult.inconclusive(ModuleId.FRIDA, String.join("; ", reasons),
                    diagnostics);
        }
        return DetectionResult.clean(ModuleId.FRIDA);
    }
}
