package com.fuad.fuadx.detection.frida;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.fuad.fuadx.detection.DetectionEvidence;
import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.DetectionSource;
import com.fuad.fuadx.detection.DetectionStatus;
import com.fuad.fuadx.heuristic.HeuristicResult;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.Collections;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

public class FridaProbeRunnerTest {

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
    public void testSuccessfulExecutionAllClean() {
        Supplier<HeuristicResult> cleanProbe = HeuristicResult::clean;
        FridaProbeRunner runner = new FridaProbeRunner(cleanProbe, cleanProbe, cleanProbe, executor, 1000);

        DetectionResult result = runner.execute();

        assertEquals(DetectionStatus.NO_DETECTION, result.getStatus());
        assertTrue(result.getEvidence().isEmpty());
    }

    @Test
    public void testExecutionWithDetection() {
        DetectionEvidence evidence = new DetectionEvidence("Test", "Method", "Found it", DetectionSource.ANDROID_SIDE);
        Supplier<HeuristicResult> cleanProbe = HeuristicResult::clean;
        Supplier<HeuristicResult> detectedProbe = () -> HeuristicResult.detected(Collections.singletonList(evidence));

        FridaProbeRunner runner = new FridaProbeRunner(cleanProbe, detectedProbe, cleanProbe, executor, 1000);

        DetectionResult result = runner.execute();

        assertEquals(DetectionStatus.DETECTED, result.getStatus());
        assertEquals(1, result.getEvidence().size());
        assertEquals("Found it", result.getEvidence().get(0).getDetails());
    }

    @Test
    public void testTimeoutHandling() {
        Supplier<HeuristicResult> cleanProbe = HeuristicResult::clean;
        Supplier<HeuristicResult> slowProbe = () -> {
            try {
                Thread.sleep(500); // Exceeds timeout
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return HeuristicResult.clean();
        };

        FridaProbeRunner runner = new FridaProbeRunner(cleanProbe, cleanProbe, slowProbe, executor, 100); // 100ms timeout

        // Pass slow probe as the third argument (libraries)
        DetectionResult result = runner.execute();

        // Since it timed out, it should be aggregated as INCONCLUSIVE
        assertEquals(DetectionStatus.INCONCLUSIVE, result.getStatus());
        assertTrue(result.getReason().contains("library: Probe exceeded evaluation deadline"));
        assertEquals(1, result.getDiagnostics().size());
        assertEquals("library", result.getDiagnostics().get(0).getProbe());
    }

    @Test
    public void testConcurrentExecutionIsRejected()
            throws InterruptedException {

        CountDownLatch started = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);

        AtomicReference<DetectionResult> firstResult =
                new AtomicReference<>();

        Supplier<HeuristicResult> blockingProbe = () -> {
            started.countDown();

            try {
                if (!release.await(5, TimeUnit.SECONDS)) {
                    return HeuristicResult.inconclusive(
                            "Test probe timed out");
                }
                return HeuristicResult.clean();

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();

                return HeuristicResult.inconclusive(
                        "Test probe interrupted");
            }
        };

        FridaProbeRunner runner =
                new FridaProbeRunner(blockingProbe, blockingProbe, blockingProbe, executor, 2500);

        Thread first = new Thread(() -> firstResult.set(
                runner.execute()
        ));

        try {
            first.start();

            assertTrue(
                    "First evaluation did not start",
                    started.await(2, TimeUnit.SECONDS)
            );

            DetectionResult second = runner.execute();

            assertEquals(
                    DetectionStatus.ERROR,
                    second.getStatus()
            );

            assertEquals(
                    "FRIDA_EVALUATION_BUSY",
                    second.getErrorCode()
            );

        } finally {
            release.countDown();
            first.join(3500);
        }

        assertFalse("First evaluation did not finish", first.isAlive());
        assertEquals(
                DetectionStatus.NO_DETECTION,
                firstResult.get().getStatus()
        );
    }
    
    @Test
    public void testDetectionIsPreservedOnPartialTimeout() {

        CountDownLatch release = new CountDownLatch(1);

        DetectionEvidence evidence = new DetectionEvidence(
                "FridaNamedThreads",
                "checkForFridaThreads",
                "gum-js-loop",
                DetectionSource.ANDROID_SIDE
        );

        Supplier<HeuristicResult> detected = () ->
                HeuristicResult.detected(
                        Collections.singletonList(evidence)
                );

        Supplier<HeuristicResult> blocking = () -> {
            try {
                if (!release.await(5, TimeUnit.SECONDS)) {
                    return HeuristicResult.inconclusive("Probe exceeded await deadline");
                }
                return HeuristicResult.clean();

            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return HeuristicResult.inconclusive(
                        "Probe interrupted");
            }
        };

        FridaProbeRunner runner =
                new FridaProbeRunner(detected, blocking, HeuristicResult::clean, executor, 300);

        try {
            DetectionResult result = runner.execute();

            assertEquals(
                    DetectionStatus.DETECTED,
                    result.getStatus()
            );

            assertEquals(1, result.getEvidence().size());
            assertEquals(1, result.getDiagnostics().size());

            assertEquals(
                    "pipe",
                    result.getDiagnostics().get(0).getProbe()
            );

            assertEquals(
                    DetectionStatus.INCONCLUSIVE,
                    result.getDiagnostics().get(0).getStatus()
            );

        } finally {
            release.countDown();
        }
    }
    
    @Test
    public void testProbeThrowsException() {
        Supplier<HeuristicResult> cleanProbe = HeuristicResult::clean;
        Supplier<HeuristicResult> crashingProbe = () -> {
            throw new RuntimeException("Simulated crash");
        };

        FridaProbeRunner runner = new FridaProbeRunner(crashingProbe, cleanProbe, cleanProbe, executor, 1000);

        DetectionResult result = runner.execute();

        // Runner should catch the exception and return an ERROR for that probe
        assertEquals(DetectionStatus.ERROR, result.getStatus());
        assertEquals("FRIDA_THREAD_PROBE_FAILED", result.getErrorCode());
        assertTrue(result.getReason().contains("thread: Probe failed: RuntimeException"));
    }
}