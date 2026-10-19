package com.fuad.fuadx.detection.runtime;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.policy.DetectionDecision;
import com.fuad.fuadx.detection.policy.DetectionPolicy;
import com.fuad.fuadx.detection.reporting.DetectionReporter;
import com.fuad.fuadx.module.ModuleId;

import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

public class DetectionDispatcherTest {

    private List<ReportCall> reportedCalls;
    private DetectionReporter mockReporter;

    // Helper class to capture reporter invocations
    private static class ReportCall {
        final DetectionResult result;
        final DetectionDecision decision;

        ReportCall(DetectionResult result, DetectionDecision decision) {
            this.result = result;
            this.decision = decision;
        }
    }

    @Before
    public void setUp() {
        reportedCalls = new ArrayList<>();
        mockReporter = (result, decision) -> reportedCalls.add(new ReportCall(result, decision));
    }

    @Test
    public void testDispatcherIgnoresContinueDecision() {
        DetectionPolicy mockPolicy = result -> DetectionDecision.CONTINUE;
        DetectionDispatcher dispatcher = new DetectionDispatcher(mockPolicy, mockReporter);

        DetectionResult cleanResult = DetectionResult.clean(ModuleId.ROOT);
        dispatcher.accept(cleanResult);

        // Since the decision is CONTINUE, the reporter should NEVER be called
        assertTrue("Reporter should not be invoked for CONTINUE decision", reportedCalls.isEmpty());
    }

    @Test
    public void testDispatcherDelegatesReportDiagnostic() {
        DetectionPolicy mockPolicy = result -> DetectionDecision.REPORT_DIAGNOSTIC;
        DetectionDispatcher dispatcher = new DetectionDispatcher(mockPolicy, mockReporter);

        DetectionResult inconclusiveResult = DetectionResult.inconclusive(ModuleId.FRIDA, "Missing");
        dispatcher.accept(inconclusiveResult);

        // Verify reporter was called exactly once with the correct arguments
        assertEquals(1, reportedCalls.size());
        assertEquals(inconclusiveResult, reportedCalls.get(0).result);
        assertEquals(DetectionDecision.REPORT_DIAGNOSTIC, reportedCalls.get(0).decision);
    }

    @Test
    public void testDispatcherDelegatesReportDetection() {
        DetectionPolicy mockPolicy = result -> DetectionDecision.REPORT_DETECTION;
        DetectionDispatcher dispatcher = new DetectionDispatcher(mockPolicy, mockReporter);

        // We use a clean result here just for simulation, 
        // the dispatcher blindly trusts the policy's decision.
        DetectionResult anyResult = DetectionResult.clean(ModuleId.DEBUG);
        dispatcher.accept(anyResult);

        assertEquals(1, reportedCalls.size());
        assertEquals(anyResult, reportedCalls.get(0).result);
        assertEquals(DetectionDecision.REPORT_DETECTION, reportedCalls.get(0).decision);
    }

    @Test(expected = NullPointerException.class)
    public void testAcceptThrowsExceptionOnNullResult() {
        DetectionPolicy mockPolicy = result -> DetectionDecision.CONTINUE;
        DetectionDispatcher dispatcher = new DetectionDispatcher(mockPolicy, mockReporter);

        dispatcher.accept(null);
    }

    @Test(expected = NullPointerException.class)
    public void testAcceptThrowsExceptionIfPolicyReturnsNull() {
        DetectionPolicy mockPolicy = result -> null;
        DetectionDispatcher dispatcher = new DetectionDispatcher(mockPolicy, mockReporter);

        DetectionResult cleanResult = DetectionResult.clean(ModuleId.ROOT);
        dispatcher.accept(cleanResult);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorRejectsNullPolicy() {
        new DetectionDispatcher(null, mockReporter);
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorRejectsNullReporter() {
        DetectionPolicy mockPolicy = result -> DetectionDecision.CONTINUE;
        new DetectionDispatcher(mockPolicy, null);
    }
}