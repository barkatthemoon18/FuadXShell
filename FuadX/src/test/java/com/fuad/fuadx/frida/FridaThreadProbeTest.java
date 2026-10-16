package com.fuad.fuadx.frida;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.fuad.fuadx.Constants;
import com.fuad.fuadx.detection.DetectionStatus;
import com.fuad.fuadx.heuristic.HeuristicResult;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class FridaThreadProbeTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private File taskDir;

    @Before
    public void setUp() throws IOException {
        taskDir = tempFolder.newFolder("task");
    }

    private void createThreadStatusFile(String threadId, String threadName) throws IOException {
        File threadDir = new File(taskDir, threadId);
        assertTrue(threadDir.mkdir());
        File statusFile = new File(threadDir, "status");
        try (FileWriter writer = new FileWriter(statusFile)) {
            writer.write("Name:\t" + threadName + "\n");
            writer.write("State:\tS (sleeping)\n");
            writer.write("Tgid:\t1234\n");
        }
    }

    @Test
    public void testCleanWhenNoSuspiciousThreads() throws IOException {
        createThreadStatusFile("1001", "main");
        createThreadStatusFile("1002", "RenderThread");

        FridaThreadProbe probe = new FridaThreadProbe(taskDir);
        HeuristicResult result = probe.scan();

        assertEquals(DetectionStatus.NO_DETECTION, result.getStatus());
        assertTrue(result.getEvidence().isEmpty());
    }

    @Test
    public void testDetectedWhenGumJsLoopThreadExists() throws IOException {
        createThreadStatusFile("1001", "main");
        createThreadStatusFile("1002", Constants.GUM_JS_LOOP);

        FridaThreadProbe probe = new FridaThreadProbe(taskDir);
        HeuristicResult result = probe.scan();

        assertEquals(DetectionStatus.DETECTED, result.getStatus());
        assertFalse(result.getEvidence().isEmpty());
        assertEquals("Suspicious thread name: " + Constants.GUM_JS_LOOP, result.getEvidence().get(0).getDetails());
    }

    @Test
    public void testDetectedWhenGmainThreadExists() throws IOException {
        createThreadStatusFile("1001", "main");
        createThreadStatusFile("1002", Constants.GMAIN);

        FridaThreadProbe probe = new FridaThreadProbe(taskDir);
        HeuristicResult result = probe.scan();

        assertEquals(DetectionStatus.DETECTED, result.getStatus());
        assertFalse(result.getEvidence().isEmpty());
        assertEquals("Suspicious thread name: " + Constants.GMAIN, result.getEvidence().get(0).getDetails());
    }

    @Test
    public void testInconclusiveWhenDirectoryNotExists() {
        File fakeDir = new File(tempFolder.getRoot(), "fake");
        FridaThreadProbe probe = new FridaThreadProbe(fakeDir);
        HeuristicResult result = probe.scan();

        assertEquals(DetectionStatus.INCONCLUSIVE, result.getStatus());
    }

    @Test
    public void testInconclusiveWhenEmptyDirectory() {
        FridaThreadProbe probe = new FridaThreadProbe(taskDir);
        HeuristicResult result = probe.scan();

        assertEquals(DetectionStatus.INCONCLUSIVE, result.getStatus());
    }

    @Test
    public void testInconclusiveWhenThreadStatusCannotBeRead() {
        // Create a thread dir without status file
        File threadDir = new File(taskDir, "1001");
        assertTrue(threadDir.mkdir());

        FridaThreadProbe probe = new FridaThreadProbe(taskDir);
        HeuristicResult result = probe.scan();

        assertEquals(DetectionStatus.INCONCLUSIVE, result.getStatus());
    }
}