package com.fuad.fuadx.detection;

import java.util.Objects;

public final class DetectionDiagnostic {
    private final DetectionStatus status;
    private final String probe;
    private final String reason;
    private final String errorCode;

    private DetectionDiagnostic(DetectionStatus status, String probe, String reason, String errorCode) {
        this.status = Objects.requireNonNull(status, "status");
        this.probe = requireText(probe, "probe");
        this.reason = requireText(reason, "reason");
        this.errorCode = errorCode;
    }

    public static DetectionDiagnostic error(String probe, String reason, String errorCode) {
        return new DetectionDiagnostic(DetectionStatus.ERROR, probe, reason, requireText(errorCode, "errorCode"));
    }

    public static DetectionDiagnostic inconclusive(String probe, String reason) {
        return new DetectionDiagnostic(DetectionStatus.INCONCLUSIVE, probe, reason, null);
    }

    private static String requireText(String value, String name) {
        Objects.requireNonNull(value, name);

        if (value.trim().isEmpty()) {
            throw new IllegalArgumentException(name + " cannot be blank");
        }
        return value;
    }

    public DetectionStatus getStatus() {
        return status;
    }

    public String getProbe() {
        return probe;
    }

    public String getReason() {
        return reason;
    }

    public String getErrorCode() {
        return errorCode;
    }
}
