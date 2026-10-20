package com.fuad.fuadx.detection.reporting;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.fuad.fuadx.detection.DetectionEvidence;
import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.DetectionSource;
import com.fuad.fuadx.detection.policy.DetectionDecision;
import com.fuad.fuadx.module.ModuleId;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

public class AsyncDetectionReporterTest {

    private AsyncDetectionReporter reporter;
    private List<DetectionResult> deliveredResults;
    private AtomicInteger overflowCount;
    private AtomicInteger failureCount;

    @Before
    public void setUp() {
        deliveredResults = Collections.synchronizedList(new ArrayList<>());
        overflowCount = new AtomicInteger(0);
        failureCount = new AtomicInteger(0);
    }

    @After
    public void tearDown() throws InterruptedException {
        if (reporter != null) {
            reporter.close();
            reporter.awaitTermination(2, TimeUnit.SECONDS);
        }
    }

    @Test
    public void testAsyncDeliverySuccess() throws InterruptedException {
        CountDownLatch deliveryLatch = new CountDownLatch(1);

        DetectionReporter mockDownstream = (result, decision) -> {
            deliveredResults.add(result);
            deliveryLatch.countDown();
        };

        reporter = new AsyncDetectionReporter(10, mockDownstream, r -> overflowCount.incrementAndGet(), e -> failureCount.incrementAndGet());

        DetectionResult mockResult = DetectionResult.detected(ModuleId.FRIDA, Collections.singletonList(new DetectionEvidence("a", "b", "c", DetectionSource.ANDROID_SIDE)));
        reporter.report(mockResult, DetectionDecision.REPORT_DETECTION);

        assertTrue("Downstream was not invoked", deliveryLatch.await(2, TimeUnit.SECONDS));
        assertEquals(1, deliveredResults.size());
        assertEquals(mockResult, deliveredResults.get(0));
        assertEquals(0, reporter.getPendingEvents());
    }

    @Test
    public void testQueueOverflowPrioritizesDetectionsOverDiagnostics() throws InterruptedException {
        // Queue capacity is exactly 1
        CountDownLatch freezeDownstream = new CountDownLatch(1);
        CountDownLatch delivered = new CountDownLatch(1);
        CountDownLatch processingStarted = new CountDownLatch(1);

        DetectionReporter blockingDownstream = (result, decision) -> {
            processingStarted.countDown();
            try {
                assertTrue("Downstream froze too long", freezeDownstream.await(5, TimeUnit.SECONDS));
                deliveredResults.add(result);
                delivered.countDown();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        };

        reporter = new AsyncDetectionReporter(1, blockingDownstream, r -> overflowCount.incrementAndGet(), e -> failureCount.incrementAndGet());

        DetectionResult diagnosticResult = DetectionResult.error(ModuleId.DEBUG, "ERR", "Diag");
        DetectionResult detectionResult = DetectionResult.detected(ModuleId.ROOT, Collections.singletonList(new DetectionEvidence("a", "b", "c", DetectionSource.ANDROID_SIDE)));

        // 1. Fill the queue with a diagnostic
        reporter.report(diagnosticResult, DetectionDecision.REPORT_DIAGNOSTIC);
        
        // Let it start processing so it pulls from the queue, freeing up the 1 slot
        assertTrue("Worker thread did not start processing in time", processingStarted.await(2, TimeUnit.SECONDS));
        
        // 2. Fill the queue again with a diagnostic (now queue size is 1)
        reporter.report(diagnosticResult, DetectionDecision.REPORT_DIAGNOSTIC);

        // 3. Push a DETECTION. Since queue is full, it should kick out the diagnostic to make room.
        reporter.report(detectionResult, DetectionDecision.REPORT_DETECTION);

        // Allow downstream to finish
        freezeDownstream.countDown();
        delivered.await(2, TimeUnit.SECONDS);
        
        // Explicitly close reporter before waiting for termination
        reporter.close();
        reporter.awaitTermination(2, TimeUnit.SECONDS);

        // We expect the dropped diagnostics count to be 1
        assertEquals("Should drop diagnostic to make room for detection", 1, reporter.getDroppedDiagnostics());
        assertEquals(0, reporter.getUndeliveredDetections());
    }

    @Test
    public void testUndeliveredDetectionTriggersOverflowHandler() throws InterruptedException {
        // Capacity 1
        CountDownLatch freezeDownstream = new CountDownLatch(1);
        CountDownLatch processingStarted = new CountDownLatch(1);

        DetectionReporter blockingDownstream = (result, decision) -> {
            processingStarted.countDown();
            try {
                freezeDownstream.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        };

        reporter = new AsyncDetectionReporter(1, blockingDownstream, r -> overflowCount.incrementAndGet(), e -> failureCount.incrementAndGet());

        DetectionResult detection1 = DetectionResult.detected(ModuleId.ROOT, Collections.singletonList(new DetectionEvidence("a", "b", "c", DetectionSource.ANDROID_SIDE)));
        DetectionResult detection2 = DetectionResult.detected(ModuleId.FRIDA, Collections.singletonList(new DetectionEvidence("a", "b", "c", DetectionSource.ANDROID_SIDE)));
        DetectionResult detection3 = DetectionResult.detected(ModuleId.DEBUG, Collections.singletonList(new DetectionEvidence("a", "b", "c", DetectionSource.ANDROID_SIDE)));

        reporter.report(detection1, DetectionDecision.REPORT_DETECTION); // Processed (pulled from queue)
        
        // Wait for worker to pull it from the queue
        assertTrue("Worker thread did not start processing in time", processingStarted.await(2, TimeUnit.SECONDS));
        
        reporter.report(detection2, DetectionDecision.REPORT_DETECTION); // Takes the 1 slot in queue
        reporter.report(detection3, DetectionDecision.REPORT_DETECTION); // Queue full, no diagnostics to kick out! OVERFLOW!

        assertEquals("Queue should be full of detections, forced to overflow", 1, overflowCount.get());
        assertEquals(1, reporter.getUndeliveredDetections());

        freezeDownstream.countDown();
        reporter.close();
        reporter.awaitTermination(2, TimeUnit.SECONDS);
    }

    @Test
    public void testDownstreamExceptionHandledGracefully() throws InterruptedException {
        CountDownLatch exceptionThrown = new CountDownLatch(1);

        DetectionReporter throwingDownstream = (result, decision) -> {
            exceptionThrown.countDown();
            throw new RuntimeException("Simulated downstream failure");
        };

        reporter = new AsyncDetectionReporter(10, throwingDownstream, r -> overflowCount.incrementAndGet(), e -> failureCount.incrementAndGet());

        // Report a diagnostic
        DetectionResult diagnosticResult = DetectionResult.error(ModuleId.DEBUG, "ERR", "Diag");
        reporter.report(diagnosticResult, DetectionDecision.REPORT_DIAGNOSTIC);

        assertTrue(exceptionThrown.await(2, TimeUnit.SECONDS));
        
        // Let the worker thread process the exception and update counters
        Thread.sleep(100);

        assertEquals("Delivery failure should be recorded", 1, reporter.getDeliveryFailures());
        assertEquals("Failure handler should be invoked", 1, failureCount.get());
    }

    @Test
    public void testCloseStopsAcceptingNewEvents() {
        DetectionReporter mockDownstream = (result, decision) -> {};
        reporter = new AsyncDetectionReporter(10, mockDownstream, r -> overflowCount.incrementAndGet(), e -> failureCount.incrementAndGet());

        reporter.close();
        
        // When closed, accepting is false.

        DetectionResult diagnosticResult = DetectionResult.error(ModuleId.DEBUG, "ERR", "Diag");
        reporter.report(diagnosticResult, DetectionDecision.REPORT_DIAGNOSTIC);

        // Since it's closed, it drops diagnostics immediately
        assertEquals(1, reporter.getDroppedDiagnostics());
        assertEquals(0, reporter.getPendingEvents());
    }
}