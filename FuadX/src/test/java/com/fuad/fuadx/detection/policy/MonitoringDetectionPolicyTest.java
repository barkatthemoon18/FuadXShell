package com.fuad.fuadx.detection.policy;

import static org.junit.Assert.assertEquals;

import com.fuad.fuadx.detection.DetectionEvidence;
import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.DetectionSource;
import com.fuad.fuadx.module.ModuleId;

import org.junit.Before;
import org.junit.Test;

import java.util.Collections;

public class MonitoringDetectionPolicyTest {

    private MonitoringDetectionPolicy policy;

    @Before
    public void setUp() {
        policy = new MonitoringDetectionPolicy();
    }

    @Test
    public void testEvaluateNoDetectionReturnsContinue() {
        DetectionResult cleanResult = DetectionResult.clean(ModuleId.ROOT);
        
        DetectionDecision decision = policy.evaluate(cleanResult);
        
        assertEquals(DetectionDecision.CONTINUE, decision);
    }

    @Test
    public void testEvaluateInconclusiveReturnsReportDiagnostic() {
        DetectionResult inconclusiveResult = DetectionResult.inconclusive(ModuleId.FRIDA, "Missing data");
        
        DetectionDecision decision = policy.evaluate(inconclusiveResult);
        
        assertEquals(DetectionDecision.REPORT_DIAGNOSTIC, decision);
    }

    @Test
    public void testEvaluateErrorReturnsReportDiagnostic() {
        DetectionResult errorResult = DetectionResult.error(ModuleId.DEBUG, "ERR_CODE", "An error occurred");
        
        DetectionDecision decision = policy.evaluate(errorResult);
        
        assertEquals(DetectionDecision.REPORT_DIAGNOSTIC, decision);
    }

    @Test
    public void testEvaluateDetectedReturnsReportDetection() {
        DetectionEvidence evidence = new DetectionEvidence("Heuristic", "Method", "Details", DetectionSource.ANDROID_SIDE);
        DetectionResult detectedResult = DetectionResult.detected(ModuleId.APK_INTEGRITY, Collections.singletonList(evidence));
        
        DetectionDecision decision = policy.evaluate(detectedResult);
        
        assertEquals(DetectionDecision.REPORT_DETECTION, decision);
    }

    @Test(expected = NullPointerException.class)
    public void testEvaluateThrowsExceptionOnNullResult() {
        policy.evaluate(null);
    }
}