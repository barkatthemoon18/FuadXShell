package com.fuad.fuadx.detection.reporting;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.fuad.fuadx.detection.DetectionDiagnostic;
import com.fuad.fuadx.detection.DetectionEvidence;
import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.DetectionSource;
import com.fuad.fuadx.detection.policy.DetectionDecision;
import com.fuad.fuadx.module.ModuleId;

import org.junit.Before;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class StructuredDetectionReporterTest {

    private List<Map<String, Object>> capturedEvents;
    private StructuredDetectionReporter reporter;

    @Before
    public void setUp() {
        capturedEvents = new ArrayList<>();
        reporter = new StructuredDetectionReporter(event -> capturedEvents.add(event));
    }

    @Test
    public void testReportIgnoresContinueDecision() {
        DetectionResult result = DetectionResult.clean(ModuleId.ROOT);
        
        reporter.report(result, DetectionDecision.CONTINUE);
        
        assertTrue("Reporter should ignore CONTINUE decisions", capturedEvents.isEmpty());
    }

    @Test
    public void testReportFormatsDetectionProperly() {
        DetectionEvidence evidence = new DetectionEvidence(
                "FridaNamedPipes", "readProcSelfFdLinks", "fd 1 references linjector", DetectionSource.ANDROID_SIDE);
        DetectionDiagnostic diagnostic = DetectionDiagnostic.error(
                "MemoryScanner", "Failed to map memory", "ERR_MEM_01");

        DetectionResult result = DetectionResult.detected(
                ModuleId.FRIDA, 
                Collections.singletonList(evidence), 
                Collections.singletonList(diagnostic));

        reporter.report(result, DetectionDecision.REPORT_DETECTION);

        assertEquals(1, capturedEvents.size());
        Map<String, Object> event = capturedEvents.get(0);

        // Verify base properties
        assertTrue(event.containsKey("timestamp"));
        assertEquals("FRIDA", event.get("module"));
        assertEquals("DETECTED", event.get("status"));
        assertEquals("REPORT_DETECTION", event.get("decision"));
        
        // Verify evidence format
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> mappedEvidence = (List<Map<String, Object>>) event.get("evidence");
        assertNotNull(mappedEvidence);
        assertEquals(1, mappedEvidence.size());
        Map<String, Object> evidenceEntry = mappedEvidence.get(0);
        assertEquals("FridaNamedPipes", evidenceEntry.get("heuristic"));
        assertEquals("readProcSelfFdLinks", evidenceEntry.get("method"));
        assertEquals("fd 1 references linjector", evidenceEntry.get("details"));
        assertEquals("ANDROID_SIDE", evidenceEntry.get("source"));
        
        // Verify diagnostic format
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> mappedDiagnostics = (List<Map<String, Object>>) event.get("diagnostics");
        assertNotNull(mappedDiagnostics);
        assertEquals(1, mappedDiagnostics.size());
        Map<String, Object> diagnosticEntry = mappedDiagnostics.get(0);
        assertEquals("MemoryScanner", diagnosticEntry.get("probe"));
        assertEquals("ERROR", diagnosticEntry.get("status"));
        assertEquals("Failed to map memory", diagnosticEntry.get("reason"));
        assertEquals("ERR_MEM_01", diagnosticEntry.get("errorCode"));
    }

    @Test
    public void testReportFormatsErrorProperly() {
        DetectionResult result = DetectionResult.error(ModuleId.DEBUG, "DEBUG_NOT_FOUND", "Debugger detection failed");

        reporter.report(result, DetectionDecision.REPORT_DIAGNOSTIC);

        assertEquals(1, capturedEvents.size());
        Map<String, Object> event = capturedEvents.get(0);

        assertEquals("DEBUG", event.get("module"));
        assertEquals("ERROR", event.get("status"));
        assertEquals("REPORT_DIAGNOSTIC", event.get("decision"));
        assertEquals("Debugger detection failed", event.get("reason"));
        assertEquals("DEBUG_NOT_FOUND", event.get("errorCode"));
        
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> mappedEvidence = (List<Map<String, Object>>) event.get("evidence");
        assertNotNull(mappedEvidence);
        assertTrue(mappedEvidence.isEmpty());
    }

    @Test
    public void testReportOmitsNullReasonAndErrorCode() {
        // An inconclusive result often has a reason but no error code.
        DetectionResult result = DetectionResult.inconclusive(ModuleId.APK_INTEGRITY, "Cannot read package signature");

        reporter.report(result, DetectionDecision.REPORT_DIAGNOSTIC);

        assertEquals(1, capturedEvents.size());
        Map<String, Object> event = capturedEvents.get(0);

        assertEquals("Cannot read package signature", event.get("reason"));
        assertFalse(event.containsKey("errorCode"));
    }

    @Test(expected = NullPointerException.class)
    public void testConstructorRejectsNullSink() {
        new StructuredDetectionReporter(null);
    }
}