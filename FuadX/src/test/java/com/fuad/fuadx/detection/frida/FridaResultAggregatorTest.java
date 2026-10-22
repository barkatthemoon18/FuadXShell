package com.fuad.fuadx.detection.frida;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.DetectionStatus;
import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;

import org.junit.Test;

public class FridaResultAggregatorTest {

    @Test
    public void testAggregateDelegatesCorrectlyToGenericAggregator() {
        java.util.Map<String, HeuristicResult> results = new java.util.HashMap<>();
        results.put("threads", HeuristicResult.clean());
        results.put("pipes", HeuristicResult.clean());
        results.put("libraries", HeuristicResult.clean());

        DetectionResult result = FridaResultAggregator.aggregate(results);

        // Since the heavy lifting is done in DetectionResultAggregator, 
        // we just need to verify that FridaResultAggregator wires it correctly 
        // with the right ModuleId and keys ("threads", "pipes", "libraries").
        assertEquals(ModuleId.FRIDA, result.getModuleId());
        assertEquals(DetectionStatus.NO_DETECTION, result.getStatus());
        assertTrue(result.getEvidence().isEmpty());
        assertNull(result.getErrorCode());
    }

    @Test
    public void testAggregateIncludesCorrectKeysInDiagnostics() {
        java.util.Map<String, HeuristicResult> results = new java.util.HashMap<>();
        results.put("threads", HeuristicResult.error("ERR_T", "Threads failed"));
        results.put("pipes", HeuristicResult.inconclusive("Pipes unreadable"));
        results.put("libraries", HeuristicResult.error("ERR_L", "Libs failed"));

        DetectionResult result = FridaResultAggregator.aggregate(results);

        assertEquals(DetectionStatus.ERROR, result.getStatus());
        assertEquals(3, result.getDiagnostics().size());
        assertEquals("thread", result.getDiagnostics().get(0).getProbe());
        assertEquals("pipe", result.getDiagnostics().get(1).getProbe());
        assertEquals("library", result.getDiagnostics().get(2).getProbe());
    }

    @Test(expected = NullPointerException.class)
    public void testNullThrowsException() {
        FridaResultAggregator.aggregate(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMissingKeysThrowsException() {
        java.util.Map<String, HeuristicResult> results = new java.util.HashMap<>();
        results.put("threads", HeuristicResult.clean());
        // Missing others
        FridaResultAggregator.aggregate(results);
    }
}