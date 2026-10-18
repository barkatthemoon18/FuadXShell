package com.fuad.fuadx.frida;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.system.ErrnoException;
import android.system.OsConstants;

import com.fuad.fuadx.Constants;
import com.fuad.fuadx.detection.DetectionStatus;
import com.fuad.fuadx.heuristic.HeuristicResult;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.IOException;

public class FridaNamedPipeProbeTest {

    @Rule
    public TemporaryFolder tempFolder = new TemporaryFolder();

    private File fdDir;

    @Before
    public void setUp() throws IOException {
        fdDir = tempFolder.newFolder("fd");
    }

    private void createFakeFd(String fdNumber) throws IOException {
        File fdFile = new File(fdDir, fdNumber);
        assertTrue(fdFile.createNewFile());
    }

    @Test
    public void testCleanWhenNoSuspiciousLinks() throws IOException {
        createFakeFd("0");
        createFakeFd("1");
        createFakeFd("2");

        FridaNamedPipeProbe.LinkResolver mockResolver = path -> {
            String name = new File(path).getName();
            if (name.equals("0")) return "/dev/null";
            if (name.equals("1")) return "socket:[12345]";
            if (name.equals("2")) return "/system/lib64/libc.so";
            return "";
        };

        FridaNamedPipeProbe probe = new FridaNamedPipeProbe(fdDir, mockResolver);
        HeuristicResult result = probe.scan();

        assertEquals(DetectionStatus.NO_DETECTION, result.getStatus());
        assertTrue(result.getEvidence().isEmpty());
    }

    @Test
    public void testDetectedWhenLinjectorLinkExists() throws IOException {
        createFakeFd("0");
        createFakeFd("1");

        FridaNamedPipeProbe.LinkResolver mockResolver = path -> {
            String name = new File(path).getName();
            if (name.equals("0")) return "/dev/null";
            
            // Note: "pipe:[1234] linjector" is a synthetic fixture meant ONLY to 
            // test the string matching logic inside FridaNamedPipeProbe. 
            // In a real Android environment, anonymous pipes show up as "pipe:[inode_number]",
            // while Frida's linjector might be found in other file descriptor types
            // (like mapped files or socket connections). This is strictly for unit testing.
            if (name.equals("1")) return "pipe:[1234] " + Constants.LINJECTOR;
            
            return "";
        };

        FridaNamedPipeProbe probe = new FridaNamedPipeProbe(fdDir, mockResolver);
        HeuristicResult result = probe.scan();

        assertEquals(DetectionStatus.DETECTED, result.getStatus());
        assertFalse(result.getEvidence().isEmpty());
        assertTrue(result.getEvidence().get(0).getDetails().contains("linjector"));
    }

    @Test
    public void testInconclusiveWhenDirectoryNotExists() {
        File fakeDir = new File(tempFolder.getRoot(), "fake");
        FridaNamedPipeProbe probe = new FridaNamedPipeProbe(fakeDir, path -> "");
        HeuristicResult result = probe.scan();

        assertEquals(DetectionStatus.INCONCLUSIVE, result.getStatus());
    }

    @Test
    public void testInconclusiveWhenEmptyDirectory() {
        FridaNamedPipeProbe probe = new FridaNamedPipeProbe(fdDir, path -> "");
        HeuristicResult result = probe.scan();

        assertEquals(DetectionStatus.INCONCLUSIVE, result.getStatus());
    }

    @Test
    public void testInconclusiveWhenLinkCannotBeRead() throws IOException {
        createFakeFd("0");
        
        FridaNamedPipeProbe.LinkResolver mockResolver = path -> {
            throw new ErrnoException("readlink", OsConstants.EACCES);
        };

        FridaNamedPipeProbe probe = new FridaNamedPipeProbe(fdDir, mockResolver);
        HeuristicResult result = probe.scan();

        assertEquals(DetectionStatus.INCONCLUSIVE, result.getStatus());
    }
    
    @Test
    public void testIgnoresNonNumericFileDescriptors() throws IOException {
        // Create an invalid FD name (e.g. some internal linux file)
        File invalidFd = new File(fdDir, "notanumber");
        assertTrue(invalidFd.createNewFile());
        
        // Even if we have a file, it shouldn't be read by the resolver
        FridaNamedPipeProbe.LinkResolver mockResolver = path -> {
            throw new RuntimeException("Should not be called");
        };

        FridaNamedPipeProbe probe = new FridaNamedPipeProbe(fdDir, mockResolver);
        HeuristicResult result = probe.scan();

        // Since it's ignored and there are no valid FDs, it should return inconclusive
        assertEquals(DetectionStatus.INCONCLUSIVE, result.getStatus());
    }
}