package com.fuad.fuadx.detection.debug;

import static org.junit.Assert.assertEquals;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.fuad.fuadx.detection.DetectionContext;
import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.DetectionStatus;
import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.module.ModuleId;
import com.fuad.fuadx.probe.ProbeDefinition;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.Arrays;

@RunWith(AndroidJUnit4.class)
public class DebugDetectionModuleInstrumentedTest {
    private ExecutorService executor;

    @Before
    public void setUp() {
        executor = Executors.newFixedThreadPool(6);
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

        DebugDetectionModule module = new DebugDetectionModule(Arrays.asList(
                probe("tracerPid", tracerExecutions, "DEBUG_TRACERPID_PROBE_FAILED"),
                probe("jdwpThreads", jdwpExecutions, "DEBUG_JDWP_THREADS_PROBE_FAILED"),
                cleanProbe("threadTracerPid", "DEBUG_THREAD_TRACERPID_PROBE_FAILED"),
                cleanProbe("tracedState", "DEBUG_TRACED_STATE_PROBE_FAILED"),
                cleanProbe("wchan", "DEBUG_WCHAN_PROBE_FAILED"),
                cleanProbe("javaDebugger", "DEBUG_JAVA_DEBUGGER_PROBE_FAILED")),
                executor, 1000);
        DetectionContext context = new DetectionContext(InstrumentationRegistry.getInstrumentation().getTargetContext());
        DetectionResult result = module.check(context);

        assertEquals(ModuleId.DEBUG, result.getModuleId());
        assertEquals(DetectionStatus.NO_DETECTION, result.getStatus());
        assertEquals(1, tracerExecutions.get());
        assertEquals(1, jdwpExecutions.get());
    }

    private static ProbeDefinition probe(String name, AtomicInteger executions, String errorCode) {
        return new ProbeDefinition(name, errorCode, () -> {
            executions.incrementAndGet();
            return HeuristicResult.clean();
        });
    }

    private static ProbeDefinition cleanProbe(String name, String errorCode) {
        return new ProbeDefinition(name, errorCode, HeuristicResult::clean);
    }
}
