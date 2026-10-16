package com.fuad.fuadx.detection;

import com.fuad.fuadx.module.ModuleId;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public final class DetectionResult {
    private final ModuleId moduleId;
    private final DetectionStatus status;
    private final List<DetectionEvidence> evidence;
    private final List<DetectionDiagnostic> diagnostics;
    private final String reason;
    private final String errorCode;
    private final long timestamp;

    private DetectionResult(ModuleId moduleId, DetectionStatus status, List<DetectionEvidence> evidence,
                           List<DetectionDiagnostic> diagnostics, String reason, String errorCode) {
        List<DetectionEvidence> evidenceCopy = new ArrayList<>(Objects.requireNonNull(evidence));
        List<DetectionDiagnostic> diagnosticCopy = new ArrayList<>(Objects.requireNonNull(diagnostics));

        if (evidenceCopy.contains(null)) {
            throw new IllegalArgumentException("Evidence cannot be null or contain null elements");
        }
        this.moduleId = Objects.requireNonNull(moduleId);
        this.status = Objects.requireNonNull(status);
        this.evidence = Collections.unmodifiableList(evidenceCopy);
        this.diagnostics = Collections.unmodifiableList(diagnosticCopy);
        this.reason = reason;
        this.errorCode = errorCode;
        this.timestamp = System.currentTimeMillis();

        if (status == DetectionStatus.DETECTED && evidence.isEmpty()) {
            throw new IllegalArgumentException("DETECTED requires positive evidence");
        }
        if (status != DetectionStatus.DETECTED && !evidence.isEmpty()) {
            throw new IllegalArgumentException("Non-DETECTED modules cannot have evidence");
        }
    }

    public static DetectionResult clean(ModuleId moduleId) {
        return new DetectionResult(moduleId, DetectionStatus.NO_DETECTION, Collections.emptyList(),
                Collections.emptyList(), null, null);
    }

    public static DetectionResult detected(ModuleId moduleId, List<DetectionEvidence> evidence) {
        return detected(moduleId, evidence, Collections.emptyList());
    }

    public static DetectionResult detected(ModuleId moduleId, List<DetectionEvidence> evidence,
                                           List<DetectionDiagnostic> diagnostics) {
        return new DetectionResult(moduleId, DetectionStatus.DETECTED, evidence, diagnostics,
                null, null);
    }

    public static DetectionResult inconclusive(ModuleId moduleId, String reason) {
        return inconclusive(moduleId, reason, Collections.emptyList());
    }

    public static DetectionResult inconclusive(ModuleId moduleId, String reason,
                                               List<DetectionDiagnostic> diagnostics) {
        return new DetectionResult(moduleId, DetectionStatus.INCONCLUSIVE, Collections.emptyList(),
                diagnostics, Objects.requireNonNull(reason), null);
    }

    public static DetectionResult error(ModuleId moduleId, String errorCode, String reason) {
        return error(moduleId, errorCode, reason, Collections.emptyList());
    }

    public static DetectionResult error(ModuleId moduleId, String errorCode, String reason,
                                        List<DetectionDiagnostic> diagnostics) {
        return new DetectionResult(moduleId, DetectionStatus.ERROR, Collections.emptyList(),
                diagnostics, Objects.requireNonNull(reason), Objects.requireNonNull(errorCode));
    }

    public ModuleId getModuleId() {
        return moduleId;
    }

    public DetectionStatus getStatus() {
        return status;
    }

    public List<DetectionEvidence> getEvidence() {
        return evidence;
    }

    public List<DetectionDiagnostic> getDiagnostics() {
        return diagnostics;
    }

    public String getReason() {
        return reason;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public long getTimestamp() {
        return timestamp;
    }
}
