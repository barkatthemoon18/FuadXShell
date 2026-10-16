package com.fuad.fuadx.frida;

import static org.junit.Assert.assertEquals;
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

public class FridaLoadedLibraryProbeTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private File mapsFile;

    @Before
    public void setUp() throws IOException {
        mapsFile = tempFolder.newFile("maps");
    }

    private void writeMapsContent(String content) throws IOException {
        try (FileWriter writer = new FileWriter(mapsFile)) {
            writer.write(content);
        }
    }

    @Test
    public void testCleanWhenNoSuspiciousLibrariesMapped() throws IOException {
        String cleanMaps = "705e4b6000-705e6b7000 r-xp 00000000 103:1c 12345 /system/lib64/libc.so\n" +
                           "705e6b7000-705e6b8000 r--p 00200000 103:1c 12345 /system/lib64/libc.so\n" +
                           "705e6b8000-705e6bb000 rw-p 00201000 103:1c 12345 /system/lib64/libc.so\n" +
                           "7fcf9cf000-7fcf9f0000 rw-p 00000000 00:00 0 [anon:dalvik-main space (region space)]\n";
        writeMapsContent(cleanMaps);

        FridaLoadedLibraryProbe probe = new FridaLoadedLibraryProbe(mapsFile);
        HeuristicResult result = probe.scan();

        assertEquals(DetectionStatus.NO_DETECTION, result.getStatus());
        assertTrue(result.getEvidence().isEmpty());
    }

    @Test
    public void testDetectedWhenFridaAgentMapped() throws IOException {
        String suspiciousMaps = "705e4b6000-705e6b7000 r-xp 00000000 103:1c 12345 /system/lib64/libc.so\n" +
                                "7550000000-7551000000 r-xp 00000000 103:1c 99999 /data/local/tmp/" + Constants.FRIDA_AGENT + ".so\n";
        writeMapsContent(suspiciousMaps);

        FridaLoadedLibraryProbe probe = new FridaLoadedLibraryProbe(mapsFile);
        HeuristicResult result = probe.scan();

        assertEquals(DetectionStatus.DETECTED, result.getStatus());
        assertEquals(1, result.getEvidence().size());
        assertTrue(result.getEvidence().get(0).getDetails().contains(Constants.FRIDA_AGENT));
    }

    @Test
    public void testDetectedWhenLinjectorMapped() throws IOException {
        String suspiciousMaps = "705e4b6000-705e6b7000 r-xp 00000000 103:1c 12345 /system/lib64/libc.so\n" +
                                "7550000000-7551000000 rw-s 00000000 00:0b 88888 /dev/ashmem/" + Constants.LINJECTOR + "\n";
        writeMapsContent(suspiciousMaps);

        FridaLoadedLibraryProbe probe = new FridaLoadedLibraryProbe(mapsFile);
        HeuristicResult result = probe.scan();

        assertEquals(DetectionStatus.DETECTED, result.getStatus());
        assertEquals(1, result.getEvidence().size());
        assertTrue(result.getEvidence().get(0).getDetails().contains(Constants.LINJECTOR));
    }

    @Test
    public void testDetectedWhenLibraryIsDeleted() throws IOException {
        // Frida often deletes its own agent from disk after loading it into memory to hide itself.
        // The maps file will show " (deleted)" at the end of the line.
        String suspiciousMaps = "7550000000-7551000000 r-xp 00000000 103:1c 99999 /data/local/tmp/" + Constants.FRIDA_GADGET + ".so (deleted)\n";
        writeMapsContent(suspiciousMaps);

        FridaLoadedLibraryProbe probe = new FridaLoadedLibraryProbe(mapsFile);
        HeuristicResult result = probe.scan();

        assertEquals(DetectionStatus.DETECTED, result.getStatus());
        assertEquals(1, result.getEvidence().size());
        assertTrue(result.getEvidence().get(0).getDetails().contains(Constants.FRIDA_GADGET));
    }

    @Test
    public void testInconclusiveWhenMapsFileMissing() {
        File missingFile = new File(tempFolder.getRoot(), "missing_maps");
        FridaLoadedLibraryProbe probe = new FridaLoadedLibraryProbe(missingFile);
        HeuristicResult result = probe.scan();

        assertEquals(DetectionStatus.INCONCLUSIVE, result.getStatus());
    }

    @Test
    public void testInconclusiveWhenEmptyFile() throws IOException {
        writeMapsContent("");
        FridaLoadedLibraryProbe probe = new FridaLoadedLibraryProbe(mapsFile);
        HeuristicResult result = probe.scan();

        assertEquals(DetectionStatus.INCONCLUSIVE, result.getStatus());
    }

    @Test
    public void testInconclusiveWhenMalformedEntriesPresentAndNoDetection() throws IOException {
        // Invalid syntax for /proc/maps format (missing fields)
        String malformedMaps = "705e4b6000-705e6b7000 invalid_perms\n" +
                               "not-a-valid-line\n";
        writeMapsContent(malformedMaps);

        FridaLoadedLibraryProbe probe = new FridaLoadedLibraryProbe(mapsFile);
        HeuristicResult result = probe.scan();

        assertEquals(DetectionStatus.INCONCLUSIVE, result.getStatus());
    }
}