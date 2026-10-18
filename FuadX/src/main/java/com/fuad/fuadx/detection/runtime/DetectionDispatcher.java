package com.fuad.fuadx.detection.runtime;

import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.policy.DetectionDecision;
import com.fuad.fuadx.detection.policy.DetectionPolicy;
import com.fuad.fuadx.detection.reporting.DetectionReporter;

import java.util.Objects;
import java.util.function.Consumer;

public final class DetectionDispatcher implements Consumer<DetectionResult> {
    private final DetectionPolicy policy;
    private final DetectionReporter reporter;

    public DetectionDispatcher(DetectionPolicy policy, DetectionReporter reporter) {
        this.policy = Objects.requireNonNull(policy);
        this.reporter = Objects.requireNonNull(reporter);
    }

    @Override
    public void accept(DetectionResult result) {
        DetectionDecision decision;

        Objects.requireNonNull(result);
        decision = Objects.requireNonNull(policy.evaluate(result), "DetectionPolicy returned null");
        switch (decision) {
            case CONTINUE:
                return;
            case REPORT_DIAGNOSTIC:
            case REPORT_DETECTION:
                reporter.report(result, decision);
                return;
            default:
                throw new IllegalStateException("Unknown decision: " + decision);
        }
    }
}
