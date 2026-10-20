package com.fuad.fuadx.detection.runtime;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.fuad.fuadx.detection.DetectionContext;
import com.fuad.fuadx.detection.DetectionModule;
import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.DetectionStatus;
import com.fuad.fuadx.module.ModuleId;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Supplier;

@RunWith(AndroidJUnit4.class)
public class DetectionSchedulerInstrumentedTest {

    private DetectionScheduler scheduler;
    private List<DetectionResult> observedResults;
    private Context appContext;

    @Before
    public void setUp() {
        appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
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
        try {
            scheduler.close();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        scheduler = new DetectionScheduler(observer);
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
    public void testCannotScheduleOnceSameModuleTwice() {
        CountDownLatch latch = new CountDownLatch(1);
        
        DetectionModule fakeModule = new DetectionModule() {
            @Override
            public ModuleId id() { return ModuleId.FRIDA; }
            @Override
            public DetectionResult check(DetectionContext ctx) {
                try {
                    latch.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return DetectionResult.clean(ModuleId.FRIDA);
            }
        };
        
        DetectionContext context = new DetectionContext(appContext);

        assertTrue(scheduler.scheduleOnce(fakeModule, context));

        // While the first is stuck executing, attempting to schedule it again should fail
        assertFalse("Should not allow duplicate scheduling once", 
                scheduler.scheduleOnce(fakeModule, context));
                
        latch.countDown();
    }

    @Test
    public void testScheduleOnceFailsIfPeriodicAlreadyRunning() {
        CountDownLatch latch = new CountDownLatch(1);
        
        // Start a periodic background evaluation (e.g. interval 10s)
        assertTrue(scheduler.schedule(ModuleId.ROOT, () -> {
            try {
                latch.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return DetectionResult.clean(ModuleId.ROOT);
        }, 10_000));
        
        DetectionModule fakeModule = new DetectionModule() {
            @Override
            public ModuleId id() { return ModuleId.ROOT; }
            @Override
            public DetectionResult check(DetectionContext ctx) {
                return DetectionResult.clean(ModuleId.ROOT);
            }
        };
        
        DetectionContext context = new DetectionContext(appContext);

        // Attempting to do a forced scheduleOnce of the same module while it has an active Registration should fail
        assertFalse("Cannot scheduleOnce if the module is already registered for periodic scanning", 
                scheduler.scheduleOnce(fakeModule, context));
                
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

        // Intentionally return FRIDA while scheduling ROOT
        Supplier<DetectionResult> probe = () -> DetectionResult.clean(ModuleId.FRIDA);

        replaceScheduler(result -> {
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

                            return DetectionResult.clean(
                                    ModuleId.DEBUG);

                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();

                            return DetectionResult.inconclusive(
                                    ModuleId.DEBUG,
                                    "Evaluation interrupted");
                        }
                    },
                    10_000
            ));

            assertTrue(debugStarted.await(
                    2, TimeUnit.SECONDS));

            assertTrue(scheduler.schedule(
                    ModuleId.FRIDA,
                    () -> DetectionResult.clean(ModuleId.FRIDA),
                    10_000
            ));

            assertTrue(
                    "Frida was blocked by Debug",
                    fridaObserved.await(2, TimeUnit.SECONDS)
            );

        } finally {
            releaseDebug.countDown();
        }
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


    @Test
    public void testScheduleOnceExecutesExactlyOnce()
            throws InterruptedException {

        AtomicInteger executions = new AtomicInteger();
        CountDownLatch observed = new CountDownLatch(1);

        replaceScheduler(result -> {
            if (result.getModuleId() == ModuleId.APK_INTEGRITY) {
                observed.countDown();
            }
        });

        assertTrue(scheduler.scheduleOnce(
                ModuleId.APK_INTEGRITY,
                () -> {
                    executions.incrementAndGet();
                    return DetectionResult.clean(
                            ModuleId.APK_INTEGRITY);
                }
        ));

        assertTrue(observed.await(2, TimeUnit.SECONDS));
        assertEquals(1, executions.get());

        // The completed one-shot registration remains reserved.
        assertFalse(scheduler.scheduleOnce(
                ModuleId.APK_INTEGRITY,
                () -> DetectionResult.clean(ModuleId.APK_INTEGRITY)
        ));

        assertEquals(1, executions.get());
    }

    @Test
    public void testOneShotDoesNotWaitForBlockedPeriodicModule()
            throws InterruptedException {

        CountDownLatch debugStarted = new CountDownLatch(1);
        CountDownLatch releaseDebug = new CountDownLatch(1);
        CountDownLatch integrityObserved = new CountDownLatch(1);

        replaceScheduler(result -> {
            if (result.getModuleId() == ModuleId.APK_INTEGRITY) {
                integrityObserved.countDown();
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
                            return DetectionResult.inconclusive(
                                    ModuleId.DEBUG,
                                    "Evaluation interrupted");
                        }
                    },
                    10000
            ));

            assertTrue(debugStarted.await(2, TimeUnit.SECONDS));

            assertTrue(scheduler.scheduleOnce(
                    ModuleId.APK_INTEGRITY,
                    () -> DetectionResult.clean(
                            ModuleId.APK_INTEGRITY)
            ));

            assertTrue(
                    "APK Integrity was blocked by Debug",
                    integrityObserved.await(2, TimeUnit.SECONDS)
            );

        } finally {
            releaseDebug.countDown();
        }
    }
}