package com.fuad.fuadx.detection.reporting;

import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.policy.DetectionDecision;

@FunctionalInterface
public interface DetectionReporter {
    void report(DetectionResult result, DetectionDecision decision);
}
