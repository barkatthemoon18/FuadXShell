package com.fuad.fuadx.detection.debug;

import static org.junit.Assert.assertEquals;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.fuad.fuadx.detection.DetectionContext;
import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.DetectionStatus;
import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

@RunWith(AndroidJUnit4.class)
public class DebugDetectionModuleInstrumentedTest {
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
        AtomicInteger tracerExecutions = new AtomicInteger();
        AtomicInteger jdwpExecutions = new AtomicInteger();

        DebugDetectionModule module = new DebugDetectionModule(() -> {
            tracerExecutions.incrementAndGet();
            return HeuristicResult.clean();
        }, () -> {
            jdwpExecutions.incrementAndGet();
            return HeuristicResult.clean();
        }, executor, 1000);
        DetectionContext context = new DetectionContext(InstrumentationRegistry.getInstrumentation().getTargetContext());
        DetectionResult result = module.check(context);

        assertEquals(ModuleId.DEBUG, result.getModuleId());
        assertEquals(DetectionStatus.NO_DETECTION, result.getStatus());
        assertEquals(1, tracerExecutions.get());
        assertEquals(1, jdwpExecutions.get());
    }
}
