package com.fuad.fuadx.detection.reporting;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class JsonlEventStoreTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private File directory;
    private File currentFile;
    private File previousFile;

    @Before
    public void setUp() throws IOException {
        directory = tempFolder.newFolder("events");
        currentFile = new File(directory, "fuadx-events.jsonl");
        previousFile = new File(directory, "fuadx-events.1.jsonl");
    }

    @Test
    public void testAcceptWritesValidJsonLine() throws IOException {
        JsonlEventStore store = new JsonlEventStore(directory, 1024);

        Map<String, Object> event = new HashMap<>();
        event.put("module", "FRIDA");
        event.put("status", "DETECTED");

        store.accept(event);

        assertTrue(currentFile.exists());
        
        try (BufferedReader reader = new BufferedReader(new FileReader(currentFile))) {
            String line = reader.readLine();
            assertTrue(line.contains("\"module\":\"FRIDA\""));
            assertTrue(line.contains("\"status\":\"DETECTED\""));
            assertNull(reader.readLine()); // Only one line
        }
    }

    @Test
    public void testFileRotationWhenMaxSizeExceeded() throws IOException {
        // Very small max file size to force rotation immediately
        JsonlEventStore store = new JsonlEventStore(directory, 50);

        Map<String, Object> event1 = new HashMap<>();
        event1.put("id", 1); // e.g. {"id":1}\n -> ~9 bytes
        
        Map<String, Object> event2 = new HashMap<>();
        event2.put("id", 2); // e.g. {"id":2}\n -> ~9 bytes

        // Write events to consume space
        store.accept(event1);
        store.accept(event2);
        store.accept(event1);
        store.accept(event2);
        
        // This next write should exceed the 50 byte limit and trigger rotation
        Map<String, Object> bigEvent = new HashMap<>();
        bigEvent.put("d", "1234567890"); // enough to surpass 50 together with the others but below 50 alone
        store.accept(bigEvent);

        // After rotation, the old data should be in previousFile
        assertTrue("Previous file should exist after rotation", previousFile.exists());
        assertTrue("Current file should exist to hold the new event", currentFile.exists());

        // Verify current file contains ONLY the new event
        try (BufferedReader reader = new BufferedReader(new FileReader(currentFile))) {
            String line = reader.readLine();
            assertTrue(line.contains("1234567890"));
            assertNull(reader.readLine());
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void testAcceptThrowsWhenPayloadExceedsMaxFileSize() {
        JsonlEventStore store = new JsonlEventStore(directory, 10);

        Map<String, Object> hugeEvent = new HashMap<>();
        hugeEvent.put("key", "This string alone is bigger than 10 bytes");

        // Should throw IllegalArgumentException
        store.accept(hugeEvent);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testConstructorThrowsIfMaxSizeIsZeroOrNegative() {
        new JsonlEventStore(directory, 0);
    }
}