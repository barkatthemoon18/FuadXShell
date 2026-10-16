package com.fuad.fuadx.detection.frida;

import static org.junit.Assert.assertEquals;
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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
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
        FridaProbeRunner runner = new FridaProbeRunner(executor, 1000);
        
        Supplier<HeuristicResult> probe = HeuristicResult::clean;

        DetectionResult result = runner.execute(probe, probe, probe);

        assertEquals(DetectionStatus.NO_DETECTION, result.getStatus());
        assertTrue(result.getEvidence().isEmpty());
    }

    @Test
    public void testExecutionWithDetection() {
        FridaProbeRunner runner = new FridaProbeRunner(executor, 1000);
        
        DetectionEvidence evidence = new DetectionEvidence("Test", "Method", "Found it", DetectionSource.ANDROID_SIDE);
        Supplier<HeuristicResult> cleanProbe = HeuristicResult::clean;
        Supplier<HeuristicResult> detectedProbe = () -> HeuristicResult.detected(Collections.singletonList(evidence));

        DetectionResult result = runner.execute(cleanProbe, detectedProbe, cleanProbe);

        assertEquals(DetectionStatus.DETECTED, result.getStatus());
        assertEquals(1, result.getEvidence().size());
        assertEquals("Found it", result.getEvidence().get(0).getDetails());
    }

    @Test
    public void testTimeoutHandling() {
        FridaProbeRunner runner = new FridaProbeRunner(executor, 100); // 100ms timeout
        
        Supplier<HeuristicResult> cleanProbe = HeuristicResult::clean;
        Supplier<HeuristicResult> slowProbe = () -> {
            try {
                Thread.sleep(500); // Exceeds timeout
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return HeuristicResult.clean();
        };

        // Pass slow probe as the third argument (libraries)
        DetectionResult result = runner.execute(cleanProbe, cleanProbe, slowProbe);

        // Since it timed out, it should be aggregated as INCONCLUSIVE
        assertEquals(DetectionStatus.INCONCLUSIVE, result.getStatus());
        assertTrue(result.getReason().contains("libraries: Probe exceeded evaluation deadline"));
        assertEquals(1, result.getDiagnostics().size());
        assertEquals("libraries", result.getDiagnostics().get(0).getProbe());
    }

    @Test
    public void testConcurrentExecutionIsRejected() throws InterruptedException {
        final FridaProbeRunner runner = new FridaProbeRunner(executor, 2000);
        final DetectionResult[] results = new DetectionResult[2];
        
        Supplier<HeuristicResult> blockingProbe = () -> {
            try {
                Thread.sleep(500);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return HeuristicResult.clean();
        };

        Thread t1 = new Thread(() -> results[0] = runner.execute(blockingProbe, blockingProbe, blockingProbe));
        Thread t2 = new Thread(() -> results[1] = runner.execute(HeuristicResult::clean, HeuristicResult::clean, HeuristicResult::clean));

        t1.start();
        // Give t1 a tiny head start to acquire the lock
        Thread.sleep(50);
        t2.start();

        t1.join();
        t2.join();

        // One of them must have succeeded cleanly
        boolean hasClean = (results[0] != null && results[0].getStatus() == DetectionStatus.NO_DETECTION) || 
                           (results[1] != null && results[1].getStatus() == DetectionStatus.NO_DETECTION);
        
        // The other one MUST have been rejected due to the AtomicBoolean lock
        boolean hasRejected = (results[0] != null && "FRIDA_EVALUATION_BUSY".equals(results[0].getErrorCode())) ||
                              (results[1] != null && "FRIDA_EVALUATION_BUSY".equals(results[1].getErrorCode()));

        assertTrue("One execution should succeed", hasClean);
        assertTrue("One execution should be rejected because it's busy", hasRejected);
    }
    
    @Test
    public void testProbeThrowsException() {
        FridaProbeRunner runner = new FridaProbeRunner(executor, 1000);
        
        Supplier<HeuristicResult> cleanProbe = HeuristicResult::clean;
        Supplier<HeuristicResult> crashingProbe = () -> {
            throw new RuntimeException("Simulated crash");
        };

        // Pass crashing probe as first argument (threads)
        DetectionResult result = runner.execute(crashingProbe, cleanProbe, cleanProbe);

        // Runner should catch the exception and return an ERROR for that probe
        assertEquals(DetectionStatus.ERROR, result.getStatus());
        assertEquals("FRIDA_THREAD_PROBE_FAILED", result.getErrorCode());
        assertTrue(result.getReason().contains("threads: Probe failed: RuntimeException"));
    }
}