package com.fuad.fuadx.detection.frida;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.fuad.fuadx.detection.DetectionEvidence;
import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.DetectionSource;
import com.fuad.fuadx.detection.DetectionStatus;
import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;

import org.junit.Test;

import java.util.Collections;

public class FridaResultAggregatorTest {

    @Test
    public void testAllCleanReturnsClean() {
        HeuristicResult clean = HeuristicResult.clean();

        DetectionResult result = FridaResultAggregator.aggregate(clean, clean, clean);

        assertEquals(ModuleId.FRIDA, result.getModuleId());
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

        // Even with errors and inconclusives, if there is a detection, it MUST return DETECTED.
        DetectionResult result = FridaResultAggregator.aggregate(error, inconclusive, detected);

        assertEquals(DetectionStatus.DETECTED, result.getStatus());
        assertEquals(1, result.getEvidence().size());
        assertEquals("TestHeuristic", result.getEvidence().get(0).getHeuristic());
        
        // Ensure diagnostics from errors and inconclusives are preserved
        assertEquals(2, result.getDiagnostics().size());
        assertEquals("threads", result.getDiagnostics().get(0).getProbe());
        assertEquals(DetectionStatus.ERROR, result.getDiagnostics().get(0).getStatus());
        assertEquals("pipes", result.getDiagnostics().get(1).getProbe());
        assertEquals(DetectionStatus.INCONCLUSIVE, result.getDiagnostics().get(1).getStatus());
    }

    @Test
    public void testMultipleDetectionsAreCombined() {
        DetectionEvidence threadEvidence = new DetectionEvidence("ThreadTest", "Method1", "Det1", DetectionSource.ANDROID_SIDE);
        DetectionEvidence pipeEvidence = new DetectionEvidence("PipeTest", "Method2", "Det2", DetectionSource.ANDROID_SIDE);

        HeuristicResult threadsDetected = HeuristicResult.detected(Collections.singletonList(threadEvidence));
        HeuristicResult pipesDetected = HeuristicResult.detected(Collections.singletonList(pipeEvidence));
        HeuristicResult clean = HeuristicResult.clean();

        DetectionResult result = FridaResultAggregator.aggregate(threadsDetected, pipesDetected, clean);

        assertEquals(DetectionStatus.DETECTED, result.getStatus());
        assertEquals(2, result.getEvidence().size());
    }

    @Test
    public void testErrorPriorityOverInconclusive() {
        HeuristicResult error = HeuristicResult.error("ERR_100", "Failed to read maps");
        HeuristicResult inconclusive = HeuristicResult.inconclusive("Task missing");
        HeuristicResult clean = HeuristicResult.clean();

        // Threads: inconclusive, Pipes: clean, Libraries: error
        DetectionResult result = FridaResultAggregator.aggregate(inconclusive, clean, error);

        assertEquals(DetectionStatus.ERROR, result.getStatus());
        assertEquals("ERR_100", result.getErrorCode());
        assertTrue(result.getReason().contains("threads: Task missing"));
        assertTrue(result.getReason().contains("libraries: Failed to read maps"));
        assertEquals(2, result.getDiagnostics().size());
        assertEquals("threads", result.getDiagnostics().get(0).getProbe());
        assertEquals(DetectionStatus.INCONCLUSIVE, result.getDiagnostics().get(0).getStatus());
        assertEquals("libraries", result.getDiagnostics().get(1).getProbe());
        assertEquals(DetectionStatus.ERROR, result.getDiagnostics().get(1).getStatus());
    }

    @Test
    public void testMultipleErrorsUsesFirstCodeAndCombinesDiagnostics() {
        HeuristicResult error1 = HeuristicResult.error("ERR_1", "Error One");
        HeuristicResult error2 = HeuristicResult.error("ERR_2", "Error Two");
        HeuristicResult clean = HeuristicResult.clean();

        // Pass error as threads (first position), error as pipes (second position)
        DetectionResult result = FridaResultAggregator.aggregate(error1, error2, clean);

        assertEquals(DetectionStatus.ERROR, result.getStatus());
        // Should pick the FIRST error code encountered
        assertEquals("ERR_1", result.getErrorCode());
        assertTrue(result.getReason().contains("threads: Error One"));
        assertTrue(result.getReason().contains("pipes: Error Two"));
        assertEquals(2, result.getDiagnostics().size());
        assertEquals("ERR_1", result.getDiagnostics().get(0).getErrorCode());
        assertEquals("ERR_2", result.getDiagnostics().get(1).getErrorCode());
    }

    @Test
    public void testAllInconclusive() {
        HeuristicResult inconclusive1 = HeuristicResult.inconclusive("Reason 1");
        HeuristicResult inconclusive2 = HeuristicResult.inconclusive("Reason 2");
        HeuristicResult inconclusive3 = HeuristicResult.inconclusive("Reason 3");

        DetectionResult result = FridaResultAggregator.aggregate(inconclusive1, inconclusive2, inconclusive3);

        assertEquals(DetectionStatus.INCONCLUSIVE, result.getStatus());
        assertTrue(result.getReason().contains("threads: Reason 1"));
        assertTrue(result.getReason().contains("pipes: Reason 2"));
        assertTrue(result.getReason().contains("libraries: Reason 3"));
        assertEquals(3, result.getDiagnostics().size());
    }

    @Test(expected = NullPointerException.class)
    public void testNullArgumentsThrowException() {
        FridaResultAggregator.aggregate(null, HeuristicResult.clean(), HeuristicResult.clean());
    }
}