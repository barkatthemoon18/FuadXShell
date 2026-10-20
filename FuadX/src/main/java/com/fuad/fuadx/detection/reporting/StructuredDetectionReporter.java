package com.fuad.fuadx.detection.reporting;

import com.fuad.fuadx.detection.DetectionDiagnostic;
import com.fuad.fuadx.detection.DetectionEvidence;
import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.policy.DetectionDecision;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

public final class StructuredDetectionReporter implements DetectionReporter {
    private final Consumer<Map<String, Object>> sink;

    public StructuredDetectionReporter(Consumer<Map<String, Object>> sink) {
        this.sink = Objects.requireNonNull(sink, "sink");
    }

    @Override
    public void report(DetectionResult result, DetectionDecision decision) {
        Map<String, Object> event = new LinkedHashMap<>();

        Objects.requireNonNull(result, "result");
        Objects.requireNonNull(decision, "decision");
        if (decision == DetectionDecision.CONTINUE) {
            return;
        }
        event.put("timestamp", result.getTimestamp());
        event.put("module", result.getModuleId().name());
        event.put("status", result.getStatus().name());
        event.put("decision", decision.name());
        if (result.getReason() != null) {
            event.put("reason", result.getReason());
        }
        if (result.getErrorCode() != null) {
            event.put("errorCode", result.getErrorCode());
        }
        event.put("evidence", mapEvidence(result.getEvidence()));
        event.put("diagnostics", mapDiagnostics(result.getDiagnostics()));
        sink.accept(Collections.unmodifiableMap(event));
    }

    private static List<Map<String, Object>> mapEvidence(List<DetectionEvidence> evidenceList) {
        Map<String, Object> entry;
        List<Map<String, Object>> items = new ArrayList<>();

        for (DetectionEvidence evidence : evidenceList) {
            entry = new LinkedHashMap<>();
            entry.put("heuristic", evidence.getHeuristic());
            entry.put("method", evidence.getMethod());
            entry.put("details", evidence.getDetails());
            entry.put("source", evidence.getSource().name());
            items.add(Collections.unmodifiableMap(entry));
        }
        return Collections.unmodifiableList(items);
    }

    private static List<Map<String, Object>> mapDiagnostics(List<DetectionDiagnostic> diagnosticsList) {
        Map<String, Object> entry;
        List<Map<String, Object>> items = new ArrayList<>();

        for (DetectionDiagnostic diagnostic : diagnosticsList) {
            entry = new LinkedHashMap<>();
            entry.put("probe", diagnostic.getProbe());
            entry.put("status", diagnostic.getStatus().name());
            entry.put("reason", diagnostic.getReason());
            if (diagnostic.getErrorCode() != null) {
                entry.put("errorCode", diagnostic.getErrorCode());
            }
            items.add(Collections.unmodifiableMap(entry));
        }
        return Collections.unmodifiableList(items);
    }
}
