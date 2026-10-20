package com.fuad.fuadx.detection;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;

import org.junit.Test;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

public class DetectionResultAggregatorTest {

    @Test
    public void testAllCleanReturnsClean() {
        Map<String, HeuristicResult> probes = new LinkedHashMap<>();
        probes.put("probe1", HeuristicResult.clean());
        probes.put("probe2", HeuristicResult.clean());

        DetectionResult result = DetectionResultAggregator.aggregate(ModuleId.ROOT, probes);

        assertEquals(ModuleId.ROOT, result.getModuleId());
        assertEquals(DetectionStatus.NO_DETECTION, result.getStatus());
        assertTrue(result.getEvidence().isEmpty());
        assertNull(result.getErrorCode());
    }

    @Test
    public void testDetectionOverridesErrorsAndInconclusives() {
        DetectionEvidence evidence = new DetectionEvidence("TestHeuristic", "TestMethod", "Details", DetectionSource.ANDROID_SIDE);
        HeuristicResult detected = HeuristicResult.detected(Collections.singletonList(evidence));
        HeuristicResult error = HeuristicResult.error("ERR_CODE", "An error occurred");
        HeuristicResult inconclusive = HeuristicResult.inconclusive("Missing data");

        Map<String, HeuristicResult> probes = new LinkedHashMap<>();
        probes.put("probeError", error);
        probes.put("probeInconclusive", inconclusive);
        probes.put("probeDetected", detected);

        DetectionResult result = DetectionResultAggregator.aggregate(ModuleId.DEBUG, probes);

        assertEquals(DetectionStatus.DETECTED, result.getStatus());
        assertEquals(1, result.getEvidence().size());
        assertEquals("TestHeuristic", result.getEvidence().get(0).getHeuristic());
        
        // Ensure diagnostics from errors and inconclusives are preserved
        assertEquals(2, result.getDiagnostics().size());
        assertEquals("probeError", result.getDiagnostics().get(0).getProbe());
        assertEquals(DetectionStatus.ERROR, result.getDiagnostics().get(0).getStatus());
        assertEquals("probeInconclusive", result.getDiagnostics().get(1).getProbe());
        assertEquals(DetectionStatus.INCONCLUSIVE, result.getDiagnostics().get(1).getStatus());
    }

    @Test
    public void testMultipleDetectionsAreCombined() {
        DetectionEvidence evidence1 = new DetectionEvidence("ThreadTest", "Method1", "Det1", DetectionSource.ANDROID_SIDE);
        DetectionEvidence evidence2 = new DetectionEvidence("PipeTest", "Method2", "Det2", DetectionSource.ANDROID_SIDE);

        HeuristicResult detected1 = HeuristicResult.detected(Collections.singletonList(evidence1));
        HeuristicResult detected2 = HeuristicResult.detected(Collections.singletonList(evidence2));

        Map<String, HeuristicResult> probes = new LinkedHashMap<>();
        probes.put("probe1", detected1);
        probes.put("probe2", detected2);
        probes.put("probe3", HeuristicResult.clean());

        DetectionResult result = DetectionResultAggregator.aggregate(ModuleId.APK_INTEGRITY, probes);

        assertEquals(DetectionStatus.DETECTED, result.getStatus());
        assertEquals(2, result.getEvidence().size());
    }

    @Test
    public void testErrorPriorityOverInconclusive() {
        HeuristicResult error = HeuristicResult.error("ERR_100", "Failed to read maps");
        HeuristicResult inconclusive = HeuristicResult.inconclusive("Task missing");

        Map<String, HeuristicResult> probes = new LinkedHashMap<>();
        probes.put("probeInconclusive", inconclusive);
        probes.put("probeClean", HeuristicResult.clean());
        probes.put("probeError", error);

        DetectionResult result = DetectionResultAggregator.aggregate(ModuleId.SSL_PINNING, probes);

        assertEquals(DetectionStatus.ERROR, result.getStatus());
        assertEquals("ERR_100", result.getErrorCode());
        assertTrue(result.getReason().contains("probeInconclusive: Task missing"));
        assertTrue(result.getReason().contains("probeError: Failed to read maps"));
        assertEquals(2, result.getDiagnostics().size());
        assertEquals("probeInconclusive", result.getDiagnostics().get(0).getProbe());
        assertEquals(DetectionStatus.INCONCLUSIVE, result.getDiagnostics().get(0).getStatus());
        assertEquals("probeError", result.getDiagnostics().get(1).getProbe());
        assertEquals(DetectionStatus.ERROR, result.getDiagnostics().get(1).getStatus());
    }

    @Test
    public void testMultipleErrorsUsesFirstCodeAndCombinesDiagnostics() {
        HeuristicResult error1 = HeuristicResult.error("ERR_1", "Error One");
        HeuristicResult error2 = HeuristicResult.error("ERR_2", "Error Two");

        Map<String, HeuristicResult> probes = new LinkedHashMap<>();
        probes.put("probeError1", error1);
        probes.put("probeError2", error2);
        probes.put("probeClean", HeuristicResult.clean());

        DetectionResult result = DetectionResultAggregator.aggregate(ModuleId.ROOT, probes);

        assertEquals(DetectionStatus.ERROR, result.getStatus());
        // Should pick the FIRST error code encountered
        assertEquals("ERR_1", result.getErrorCode());
        assertTrue(result.getReason().contains("probeError1: Error One"));
        assertTrue(result.getReason().contains("probeError2: Error Two"));
        assertEquals(2, result.getDiagnostics().size());
        assertEquals("ERR_1", result.getDiagnostics().get(0).getErrorCode());
        assertEquals("ERR_2", result.getDiagnostics().get(1).getErrorCode());
    }

    @Test
    public void testAllInconclusive() {
        Map<String, HeuristicResult> probes = new LinkedHashMap<>();
        probes.put("probe1", HeuristicResult.inconclusive("Reason 1"));
        probes.put("probe2", HeuristicResult.inconclusive("Reason 2"));

        DetectionResult result = DetectionResultAggregator.aggregate(ModuleId.FRIDA, probes);

        assertEquals(DetectionStatus.INCONCLUSIVE, result.getStatus());
        assertTrue(result.getReason().contains("probe1: Reason 1"));
        assertTrue(result.getReason().contains("probe2: Reason 2"));
        assertEquals(2, result.getDiagnostics().size());
    }

    @Test(expected = NullPointerException.class)
    public void testNullModuleIdThrowsException() {
        DetectionResultAggregator.aggregate(null, Collections.emptyMap());
    }

    @Test(expected = NullPointerException.class)
    public void testNullProbesThrowsException() {
        DetectionResultAggregator.aggregate(ModuleId.ROOT, null);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testBlankProbeNameThrowsException() {
        Map<String, HeuristicResult> probes = new LinkedHashMap<>();
        probes.put("   ", HeuristicResult.clean());
        DetectionResultAggregator.aggregate(ModuleId.ROOT, probes);
    }
    
    @Test(expected = NullPointerException.class)
    public void testNullProbeResultThrowsException() {
        Map<String, HeuristicResult> probes = new LinkedHashMap<>();
        probes.put("probe1", null);
        DetectionResultAggregator.aggregate(ModuleId.ROOT, probes);
    }
}