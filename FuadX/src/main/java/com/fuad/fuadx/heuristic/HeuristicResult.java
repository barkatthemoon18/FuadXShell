package com.fuad.fuadx.heuristic;

import com.fuad.fuadx.detection.DetectionEvidence;
import com.fuad.fuadx.detection.DetectionStatus;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

public final class HeuristicResult {
    private final DetectionStatus status;
    private final List<DetectionEvidence> evidence;
    private final String reason;
    private final String errorCode;

    private HeuristicResult(DetectionStatus status, List<DetectionEvidence> evidence, String reason,
                            String errorCode) {
        List<DetectionEvidence> evidenceCopy = new ArrayList<>(Objects.requireNonNull(evidence));

        if (evidenceCopy.contains(null)) {
            throw new IllegalArgumentException("Evidence cannot be null or contain null elements");
        }
        this.status = Objects.requireNonNull(status);
        this.evidence = Collections.unmodifiableList(evidenceCopy);
        this.reason = reason;
        this.errorCode = errorCode;

        if (status == DetectionStatus.DETECTED && evidence.isEmpty()) {
            throw new IllegalArgumentException("DETECTED requires positive evidence");
        }
        if (status != DetectionStatus.DETECTED && !evidence.isEmpty()) {
            throw new IllegalArgumentException("Non-DETECTED modules cannot have evidence");
        }
    }

    public static HeuristicResult clean() {
        return new HeuristicResult(DetectionStatus.NO_DETECTION, Collections.emptyList(), null, null);
    }

    public static HeuristicResult detected(List<DetectionEvidence> evidence) {
        return new HeuristicResult(DetectionStatus.DETECTED, evidence, null, null);
    }

    public static HeuristicResult inconclusive(String reason) {
        return new HeuristicResult(DetectionStatus.INCONCLUSIVE, Collections.emptyList(),
                Objects.requireNonNull(reason), null);
    }

    public static HeuristicResult error(String errorCode, String reason) {
        return new HeuristicResult(DetectionStatus.ERROR, Collections.emptyList(),
                Objects.requireNonNull(reason), Objects.requireNonNull(errorCode));
    }

    public List<DetectionEvidence> getEvidence() {
        return evidence;
    }

    public String getReason() {
        return reason;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public DetectionStatus getStatus() {
        return status;
    }
}
