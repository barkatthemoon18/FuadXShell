package com.fuad.fuadx.detection.debug;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.DetectionStatus;
import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;

import org.junit.Test;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class DebugResultAggregatorTest {

    @Test
    public void testAggregateDelegatesCorrectlyToGenericAggregator() {
        Map<String, HeuristicResult> results = new HashMap<>();
        results.put("tracerPid", HeuristicResult.clean());
        results.put("jdwpThreads", HeuristicResult.clean());
        addCleanDebugProbes(results);

        DetectionResult result = DebugResultAggregator.aggregate(results);

        assertEquals(ModuleId.DEBUG, result.getModuleId());
        assertEquals(DetectionStatus.NO_DETECTION, result.getStatus());
        assertTrue(result.getEvidence().isEmpty());
        assertNull(result.getErrorCode());
    }

    @Test
    public void testAggregateIncludesCorrectKeysInDiagnostics() {
        Map<String, HeuristicResult> results = new HashMap<>();
        results.put("tracerPid", HeuristicResult.error("ERR_TRACER", "Tracer failed"));
        results.put("jdwpThreads", HeuristicResult.inconclusive("JDWP unreadable"));
        addCleanDebugProbes(results);

        DetectionResult result = DebugResultAggregator.aggregate(results);

        assertEquals(DetectionStatus.ERROR, result.getStatus());
        assertEquals(2, result.getDiagnostics().size());
        
        // Ensure the hardcoded keys are correctly extracted and ordered
        assertEquals("tracerPid", result.getDiagnostics().get(0).getProbe());
        assertEquals("jdwpThreads", result.getDiagnostics().get(1).getProbe());
    }

    @Test(expected = NullPointerException.class)
    public void testNullMapThrowsException() {
        DebugResultAggregator.aggregate(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMissingKeysThrowsException() {
        Map<String, HeuristicResult> results = new HashMap<>();
        results.put("tracerPid", HeuristicResult.clean());
        // Missing "jdwpThreads" key
        DebugResultAggregator.aggregate(results);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testExtraKeysThrowsException() {
        Map<String, HeuristicResult> results = new HashMap<>();
        results.put("tracerPid", HeuristicResult.clean());
        results.put("jdwpThreads", HeuristicResult.clean());
        results.put("extraKey", HeuristicResult.clean());
        // Should throw because size != 2
        DebugResultAggregator.aggregate(results);
    }

    private static void addCleanDebugProbes(Map<String, HeuristicResult> results) {
        results.put("threadTracerPid", HeuristicResult.clean());
        results.put("tracedState", HeuristicResult.clean());
        results.put("wchan", HeuristicResult.clean());
        results.put("javaDebugger", HeuristicResult.clean());
    }
}