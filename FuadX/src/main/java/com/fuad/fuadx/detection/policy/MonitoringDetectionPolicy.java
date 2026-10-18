package com.fuad.fuadx.detection.policy;

import com.fuad.fuadx.detection.DetectionResult;

import java.util.Objects;

public final class MonitoringDetectionPolicy implements DetectionPolicy {
    @Override
    public DetectionDecision evaluate(DetectionResult result) {
        Objects.requireNonNull(result, "result");

        switch(result.getStatus()) {
            case NO_DETECTION:
                return DetectionDecision.CONTINUE;
            case INCONCLUSIVE:
            case ERROR:
                return DetectionDecision.REPORT_DIAGNOSTIC;
            case DETECTED:
                return DetectionDecision.REPORT_DETECTION;
            default:
                throw new IllegalStateException("Unknown detection status");
        }
    }
}
