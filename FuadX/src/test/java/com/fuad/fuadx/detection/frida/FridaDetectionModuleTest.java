package com.fuad.fuadx.detection.frida;

import static org.junit.Assert.assertEquals;

import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.DetectionStatus;
import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

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
        FridaDetectionModule module = new FridaDetectionModule(
                HeuristicResult::clean,
                HeuristicResult::clean,
                HeuristicResult::clean,
                executor,
                1000
        );

        module.check(null);
    }
}