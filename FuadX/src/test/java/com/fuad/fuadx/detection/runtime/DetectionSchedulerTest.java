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
import java.util.function.Consumer;
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
    public void tearDown() {
        if (scheduler != null) {
            scheduler.close();
        }
    }

    private void replaceScheduler(Consumer<DetectionResult> observer) {
        scheduler.close();
        scheduler = new DetectionScheduler(observer);
    }

    @Test
    public void testScheduleAndExecuteSuccess() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(2);

        Supplier<DetectionResult> probe = () -> {
            latch.countDown();
            return DetectionResult.clean(ModuleId.ROOT);
        };

        assertTrue(scheduler.schedule(ModuleId.ROOT, probe, 50));

        assertTrue("Scheduler did not execute in time", latch.await(2, TimeUnit.SECONDS));

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
    public void testCannotScheduleOnceSameModuleTwice() {
        CountDownLatch latch = new CountDownLatch(1);
        
        Supplier<DetectionResult> probe = () -> {
            try {
                latch.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return DetectionResult.clean(ModuleId.FRIDA);
        };
        
        // This tests the package-private API logic
        assertTrue(scheduler.scheduleOnce(ModuleId.FRIDA, probe));

        // While the first is stuck executing, attempting to schedule it again should fail
        assertFalse("Should not allow duplicate scheduling once", 
                scheduler.scheduleOnce(ModuleId.FRIDA, () -> DetectionResult.clean(ModuleId.FRIDA)));
                
        latch.countDown();
    }

    @Test
    public void testScheduleOnceFailsIfPeriodicAlreadyRunning() {
        CountDownLatch latch = new CountDownLatch(1);
        
        assertTrue(scheduler.schedule(ModuleId.ROOT, () -> {
            try {
                latch.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return DetectionResult.clean(ModuleId.ROOT);
        }, 10_000));
        
        assertFalse("Cannot scheduleOnce if the module is already registered for periodic scanning", 
                scheduler.scheduleOnce(ModuleId.ROOT, () -> DetectionResult.clean(ModuleId.ROOT)));
                
        latch.countDown();
    }

    @Test
    public void testStopCancelsModule() throws InterruptedException {
        CountDownLatch executionLatch = new CountDownLatch(1);

        Supplier<DetectionResult> probe = () -> {
            executionLatch.countDown();
            return DetectionResult.clean(ModuleId.DEBUG);
        };

        assertTrue(scheduler.schedule(ModuleId.DEBUG, probe, 50));
        assertTrue(executionLatch.await(1, TimeUnit.SECONDS));
        assertTrue(scheduler.stop(ModuleId.DEBUG));

        int observedCountBefore = observedResults.size();
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

        replaceScheduler(result -> {
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

        replaceScheduler(result -> {
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

        Supplier<DetectionResult> probe = () -> DetectionResult.clean(ModuleId.FRIDA);

        replaceScheduler(result -> {
            observedResults.add(result);
            latch.countDown();
        });

        assertTrue(scheduler.schedule(ModuleId.ROOT, probe, 50));
        assertTrue(latch.await(1, TimeUnit.SECONDS));

        DetectionResult result = observedResults.get(0);
        assertEquals(ModuleId.ROOT, result.getModuleId());
        assertEquals(DetectionStatus.ERROR, result.getStatus());
        assertEquals("MODULE_EXECUTION_FAILED", result.getErrorCode());
        assertTrue(result.getReason().contains("IllegalStateException"));
    }

    @Test
    public void testSlowModuleDoesNotBlockAnotherModule() throws InterruptedException {

        CountDownLatch debugStarted = new CountDownLatch(1);
        CountDownLatch releaseDebug = new CountDownLatch(1);
        CountDownLatch fridaObserved = new CountDownLatch(1);

        replaceScheduler(result -> {
            observedResults.add(result);

            if (result.getModuleId() == ModuleId.FRIDA) {
                fridaObserved.countDown();
            }
        });

        try {
            assertTrue(scheduler.schedule(
                    ModuleId.DEBUG,
                    () -> {
                        debugStarted.countDown();
                        try {
                            releaseDebug.await();
                            return DetectionResult.clean(ModuleId.DEBUG);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            return DetectionResult.inconclusive(ModuleId.DEBUG, "Evaluation interrupted");
                        }
                    },
                    10_000
            ));

            assertTrue(debugStarted.await(2, TimeUnit.SECONDS));

            assertTrue(scheduler.schedule(
                    ModuleId.FRIDA,
                    () -> DetectionResult.clean(ModuleId.FRIDA),
                    10_000
            ));

            assertTrue("Frida was blocked by Debug", fridaObserved.await(2, TimeUnit.SECONDS));

        } finally {
            releaseDebug.countDown();
        }
    }

    @Test(expected = IllegalStateException.class)
    public void testScheduleThrowsIfClosed() {
        scheduler.close();
        scheduler.schedule(ModuleId.ROOT, () -> DetectionResult.clean(ModuleId.ROOT), 100);
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void testScheduleThrowsIfIntervalIsNegative() {
        scheduler.schedule(ModuleId.ROOT, () -> DetectionResult.clean(ModuleId.ROOT), -5);
    }
}