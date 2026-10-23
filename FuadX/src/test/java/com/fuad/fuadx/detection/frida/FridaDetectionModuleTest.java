package com.fuad.fuadx.detection.frida;

import static org.junit.Assert.assertEquals;

import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.DetectionStatus;
import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;
import com.fuad.fuadx.probe.ProbeDefinition;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.Arrays;

public class FridaDetectionModuleTest {

    private ExecutorService executor;

    @Before
    public void setUp() {
        executor = Executors.newFixedThreadPool(3);
    }

    @After
    public void tearDown() {
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    @Test
    public void testModuleId() {
        FridaDetectionModule module = new FridaDetectionModule();
        assertEquals(ModuleId.FRIDA, module.id());
    }

    @Test(expected = NullPointerException.class)
    public void testCheckRejectsNullContext() {
        FridaDetectionModule module = new FridaDetectionModule(Arrays.asList(
                probe("threads"), probe("pipes"), probe("libraries")),
                executor, 1000);

        module.check(null);
    }

    private static ProbeDefinition probe(String name) {
        return new ProbeDefinition(name, name.toUpperCase() + "_FAILED", HeuristicResult::clean);
    }
}