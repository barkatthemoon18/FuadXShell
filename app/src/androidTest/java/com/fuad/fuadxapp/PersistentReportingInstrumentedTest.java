
package com.fuad.fuadxapp;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.policy.MonitoringDetectionPolicy;
import com.fuad.fuadx.detection.reporting.AsyncDetectionReporter;
import com.fuad.fuadx.detection.reporting.JsonlEventStore;
import com.fuad.fuadx.detection.reporting.StructuredDetectionReporter;
import com.fuad.fuadx.detection.runtime.DetectionDispatcher;
import com.fuad.fuadx.module.ModuleId;

import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public class PersistentReportingInstrumentedTest {

    @Test
    public void syntheticDiagnosticIsPersisted() throws Exception {

        Context context = InstrumentationRegistry
                .getInstrumentation()
                .getTargetContext();

        // Dedicated directory: no interference with the live RASP.
        File directory = new File(
                context.getNoBackupFilesDir(),
                "fuadx-detections-test"
        );

        File file = new File(directory, "fuadx-events.jsonl");

        if (file.exists()) {
            assertTrue("Unable to reset test file", file.delete());
        }

        JsonlEventStore store = new JsonlEventStore(
                directory,
                1024L * 1024L
        );

        AtomicInteger failures = new AtomicInteger();
        AtomicInteger overflows = new AtomicInteger();

        AsyncDetectionReporter reporter = new AsyncDetectionReporter(
                8,
                new StructuredDetectionReporter(store),
                result -> overflows.incrementAndGet(),
                error -> failures.incrementAndGet()
        );

        try {
            DetectionDispatcher dispatcher = new DetectionDispatcher(
                    new MonitoringDetectionPolicy(),
                    reporter
            );

            dispatcher.accept(DetectionResult.error(
                    ModuleId.FRIDA,
                    "REPORTING_SMOKE_TEST",
                    "Synthetic instrumentation test"
            ));

        } finally {
            reporter.close();
        }

        assertTrue("Reporting worker did not terminate",
                reporter.awaitTermination(5, TimeUnit.SECONDS));

        assertEquals(0, failures.get());
        assertEquals(0, overflows.get());
        assertEquals(0, reporter.getDeliveryFailures());

        assertTrue("JSONL file was not created", file.isFile());

        boolean found = false;

        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(
                        new FileInputStream(file),
                        StandardCharsets.UTF_8))) {

            String line;

            while ((line = reader.readLine()) != null) {
                JSONObject event = new JSONObject(line);

                if ("REPORTING_SMOKE_TEST".equals(
                        event.optString("errorCode"))) {

                    assertEquals("FRIDA",
                            event.getString("module"));

                    assertEquals("ERROR",
                            event.getString("status"));

                    assertEquals("REPORT_DIAGNOSTIC",
                            event.getString("decision"));

                    found = true;
                }
            }
        }

        assertTrue("Synthetic event was not persisted", found);
    }
}
