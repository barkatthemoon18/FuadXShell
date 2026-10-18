package com.fuad.fuadx.detection.policy;

import com.fuad.fuadx.detection.DetectionResult;

@FunctionalInterface
public interface DetectionPolicy {
    DetectionDecision evaluate(DetectionResult result);
}
