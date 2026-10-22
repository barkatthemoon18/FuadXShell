package com.fuad.fuadx.probe;

import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.heuristic.HeuristicResult;

public interface ProbeRunner {
    DetectionResult execute();
    HeuristicResult unexpectedFailure(ProbeDefinition probe, RuntimeException failure);
}
