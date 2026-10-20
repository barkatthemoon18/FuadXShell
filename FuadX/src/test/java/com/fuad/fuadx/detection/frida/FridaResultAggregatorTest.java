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
        HeuristicResult clean = HeuristicResult.clean();

        DetectionResult result = FridaResultAggregator.aggregate(clean, clean, clean);

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
        HeuristicResult errorThreads = HeuristicResult.error("ERR_T", "Threads failed");
        HeuristicResult inconclusivePipes = HeuristicResult.inconclusive("Pipes unreadable");
        HeuristicResult errorLibs = HeuristicResult.error("ERR_L", "Libs failed");

        DetectionResult result = FridaResultAggregator.aggregate(errorThreads, inconclusivePipes, errorLibs);

        assertEquals(DetectionStatus.ERROR, result.getStatus());
        assertEquals(3, result.getDiagnostics().size());
        
        // Ensure the hardcoded keys are correct
        assertEquals("threads", result.getDiagnostics().get(0).getProbe());
        assertEquals("pipes", result.getDiagnostics().get(1).getProbe());
        assertEquals("libraries", result.getDiagnostics().get(2).getProbe());
    }

    @Test(expected = NullPointerException.class)
    public void testNullThreadsThrowsException() {
        FridaResultAggregator.aggregate(null, HeuristicResult.clean(), HeuristicResult.clean());
    }

    @Test(expected = NullPointerException.class)
    public void testNullPipesThrowsException() {
        FridaResultAggregator.aggregate(HeuristicResult.clean(), null, HeuristicResult.clean());
    }

    @Test(expected = NullPointerException.class)
    public void testNullLibrariesThrowsException() {
        FridaResultAggregator.aggregate(HeuristicResult.clean(), HeuristicResult.clean(), null);
    }
}