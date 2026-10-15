package com.fuad.fuadx.frida;

import com.fuad.fuadx.Constants;
import com.fuad.fuadx.detection.DetectionEvidence;
import com.fuad.fuadx.detection.DetectionSource;
import com.fuad.fuadx.heuristic.HeuristicResult;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public final class FridaThreadProbe {
    private final File taskDirectory;

    public FridaThreadProbe() {
        this(new File(Constants.PATH_PROC_SELF_TASK));
    }

    FridaThreadProbe(File taskDirectory) {
        this.taskDirectory = Objects.requireNonNull(taskDirectory);
    }

    public HeuristicResult scan() {
        List<DetectionEvidence> evidence = new ArrayList<>();
        File[] threads;
        File statusFile;
        String line;
        String name;
        boolean foundName = false;
        int inspected = 0;
        int failed = 0;

        if (!taskDirectory.isDirectory()) {
            return HeuristicResult.inconclusive("Process task directory is unavailable");
        }
        threads = taskDirectory.listFiles();
        if (threads == null) {
            return HeuristicResult.error("FRIDA_THREAD_ENUM_FAILED", "Unable to enumerate process threads");
        }
        if (threads.length == 0) {
            return HeuristicResult.inconclusive("Process thread enumeration returned no entries");
        }
        for (File thread : threads) {
            if (!thread.isDirectory()) {
                continue;
            }
            statusFile = new File(thread, "status");
            try (BufferedReader reader = new BufferedReader(new FileReader(statusFile))) {
                while ((line = reader.readLine()) != null) {
                    if (!line.startsWith("Name:")) {
                        continue;
                    }
                    foundName = true;
                    inspected++;
                    name = line.substring(5).trim();
                    if (isSuspiciousThread(name)) {
                        evidence.add(new DetectionEvidence("FridaNamedThreads",
                                "checkForFridaThreads", "Suspicious thread name: " + name,
                                DetectionSource.ANDROID_SIDE));
                    }
                    break;
                }
                if (!foundName) {
                    failed++;
                }
            }
            catch (FileNotFoundException e) {
                if (thread.exists()) {
                    failed++;
                }
            }
            catch (IOException e) {
                failed++;
            }
        }
        if (!evidence.isEmpty()) {
            return HeuristicResult.detected(evidence);
        }
        if (failed > 0) {
            return HeuristicResult.inconclusive("Some thread status filed could not be inspected");
        }
        if (inspected == 0) {
            return HeuristicResult.inconclusive("No thread status could be inspected");
        }
        return HeuristicResult.clean();
    }

    private static boolean isSuspiciousThread(String name) {
        return Constants.GUM_JS_LOOP.equalsIgnoreCase(name) || Constants.GMAIN.equalsIgnoreCase(name);
    }
}
