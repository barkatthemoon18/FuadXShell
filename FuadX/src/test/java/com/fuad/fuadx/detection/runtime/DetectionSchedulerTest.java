package com.fuad.fuadx.detection.runtime;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.DetectionStatus;
import com.fuad.fuadx.module.ModuleId;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.Supplier;

public class DetectionSchedulerTest {

    private DetectionScheduler scheduler;
    private List<DetectionResult> observedResults;

    @Before
    public void setUp() {
        observedResults = Collections.synchronizedList(new ArrayList<>());
        scheduler = new DetectionScheduler(result -> observedResults.add(result));
    }

    @After
    public void tearDown() throws Exception {
        if (scheduler != null) {
            scheduler.close();
        }
    }

    @Test
    public void testScheduleAndExecuteSuccess() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(2);

        Supplier<DetectionResult> probe = () -> {
            latch.countDown();
            return DetectionResult.clean(ModuleId.ROOT);
        };

        assertTrue(scheduler.schedule(ModuleId.ROOT, probe, 50)); // 50ms interval

        // Wait for it to execute at least twice
        assertTrue("Scheduler did not execute in time", latch.await(2, TimeUnit.SECONDS));

        // Let's verify we got some results
        assertFalse(observedResults.isEmpty());
        for (DetectionResult result : observedResults) {
            assertEquals(ModuleId.ROOT, result.getModuleId());
            assertEquals(DetectionStatus.NO_DETECTION, result.getStatus());
        }
    }

    @Test
    public void testCannotScheduleSameModuleTwice() {
        assertTrue(scheduler.schedule(ModuleId.FRIDA, () -> DetectionResult.clean(ModuleId.FRIDA), 100));
        assertFalse("Should not allow duplicate scheduling", 
                scheduler.schedule(ModuleId.FRIDA, () -> DetectionResult.clean(ModuleId.FRIDA), 100));
    }

    @Test
    public void testStopCancelsModule() throws InterruptedException {
        CountDownLatch executionLatch = new CountDownLatch(1);

        Supplier<DetectionResult> probe = () -> {
            executionLatch.countDown();
            return DetectionResult.clean(ModuleId.DEBUG);
        };

        assertTrue(scheduler.schedule(ModuleId.DEBUG, probe, 50));

        // Wait for first execution
        assertTrue(executionLatch.await(1, TimeUnit.SECONDS));

        // Stop it
        assertTrue(scheduler.stop(ModuleId.DEBUG));

        int observedCountBefore = observedResults.size();

        // Wait extra time to ensure it does not run again
        Thread.sleep(200);

        assertEquals("Should not have executed any more after being stopped",
                observedCountBefore, observedResults.size());
    }

    @Test
    public void testProbeExceptionCaughtAndReportedAsError() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);

        Supplier<DetectionResult> probe = () -> {
            throw new RuntimeException("Simulated crash");
        };

        scheduler = new DetectionScheduler(result -> {
            observedResults.add(result);
            latch.countDown();
        });

        assertTrue(scheduler.schedule(ModuleId.APK_INTEGRITY, probe, 50));

        assertTrue(latch.await(1, TimeUnit.SECONDS));

        DetectionResult result = observedResults.get(0);
        assertEquals(ModuleId.APK_INTEGRITY, result.getModuleId());
        assertEquals(DetectionStatus.ERROR, result.getStatus());
        assertEquals("MODULE_EXECUTION_FAILED", result.getErrorCode());
        assertTrue(result.getReason().contains("RuntimeException"));
    }

    @Test
    public void testProbeReturnsNullReportedAsError() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);

        Supplier<DetectionResult> probe = () -> null;

        scheduler = new DetectionScheduler(result -> {
            observedResults.add(result);
            latch.countDown();
        });

        assertTrue(scheduler.schedule(ModuleId.SSL_PINNING, probe, 50));

        assertTrue(latch.await(1, TimeUnit.SECONDS));

        DetectionResult result = observedResults.get(0);
        assertEquals(ModuleId.SSL_PINNING, result.getModuleId());
        assertEquals(DetectionStatus.ERROR, result.getStatus());
        assertEquals("MODULE_EXECUTION_FAILED", result.getErrorCode());
        assertTrue(result.getReason().contains("NullPointerException"));
    }

    @Test
    public void testProbeReturnsWrongModuleIdReportedAsError() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);

        // Intentionally return FRIDA while scheduling ROOT
        Supplier<DetectionResult> probe = () -> DetectionResult.clean(ModuleId.FRIDA);

        scheduler = new DetectionScheduler(result -> {
            observedResults.add(result);
            latch.countDown();
        });

        assertTrue(scheduler.schedule(ModuleId.ROOT, probe, 50));

        assertTrue(latch.await(1, TimeUnit.SECONDS));

        DetectionResult result = observedResults.get(0);
        // The error itself is reported under the scheduled module ID
        assertEquals(ModuleId.ROOT, result.getModuleId());
        assertEquals(DetectionStatus.ERROR, result.getStatus());
        assertEquals("MODULE_EXECUTION_FAILED", result.getErrorCode());
        assertTrue(result.getReason().contains("IllegalStateException"));
    }

    @Test(expected = IllegalStateException.class)
    public void testScheduleThrowsIfClosed() throws Exception {
        scheduler.close();
        scheduler.schedule(ModuleId.ROOT, () -> DetectionResult.clean(ModuleId.ROOT), 100);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testScheduleThrowsIfIntervalIsNegative() {
        scheduler.schedule(ModuleId.ROOT, () -> DetectionResult.clean(ModuleId.ROOT), -5);
    }
}