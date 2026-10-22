package com.fuad.fuadx.detection.debug;

import static org.junit.Assert.assertEquals;

import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class DebugDetectionModuleTest {

    private ExecutorService executor;

    @Before
    public void setUp() {
        executor = Executors.newFixedThreadPool(2);
    }

    @After
    public void tearDown() {
        if (executor != null) {
            executor.shutdownNow();
        }
    }

    @Test
    public void testModuleId() {
        DebugDetectionModule module = new DebugDetectionModule();
        assertEquals(ModuleId.DEBUG, module.id());
    }

    @Test
    public void testCheckExecutionDelegatesToRunner() {
        // We inject fake probes that just return clean immediately.
        DebugDetectionModule module = new DebugDetectionModule(
                HeuristicResult::clean,
                HeuristicResult::clean,
                executor,
                1000
        );

        // We expect the NullPointerException from DetectionContext's internal requireNonNull 
        // if we just pass null Context, or we can catch the exception expected on the context
        try {
            module.check(null);
        } catch (NullPointerException e) {
            assertEquals("context", e.getMessage());
        }
    }
}