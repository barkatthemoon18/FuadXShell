package com.fuad.fuadx.debug;

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

public final class DebugThreadTracerPidProbe {
    private final File taskDirectory;

    public DebugThreadTracerPidProbe() {
        this(new File(Constants.PATH_PROC_SELF_TASK));
    }

    public DebugThreadTracerPidProbe(File taskDirectory) {
        this.taskDirectory = Objects.requireNonNull(taskDirectory, "taskDirectory");
    }

    public HeuristicResult scan() {
        List<DetectionEvidence> evidences = new ArrayList<>();
        File[] threads;
        File statusFile;
        String line;
        String raw;
        boolean found = false;
        int inspected = 0;
        int failed = 0;
        int invalid = 0;
        int tracerPid;

        if (!taskDirectory.isDirectory()) {
            return HeuristicResult.inconclusive("Thread directory unavailable");
        }
        threads = taskDirectory.listFiles();
        if (threads == null) {
            return HeuristicResult.error("DEBUG_THREAD_TRACERPID_ENUM_FAILED",
                    "Unable to enumerate process threads");
        }
        for (File thread : threads) {
            if (!thread.isDirectory()) {
                continue;
            }
            statusFile = new File(thread, "status");
            try (BufferedReader reader = new BufferedReader(new FileReader(statusFile))) {
                while ((line = reader.readLine()) != null) {
                    if (!line.startsWith("TracerPid:")) {
                        continue;
                    }
                    found = true;
                    raw = line.substring("TracerPid:".length()).trim();
                    try {
                        tracerPid = Integer.parseInt(raw);
                        if (tracerPid < 0) {
                            invalid++;
                        }
                        else {
                            inspected++;
                            if (tracerPid > 0) {
                                evidences.add(new DetectionEvidence("ThreadTracerPid",
                                        "readThreadStatus", "tid=" + thread.getName() +
                                        ", TracerPid=" + tracerPid, DetectionSource.ANDROID_SIDE));
                            }
                        }
                    }
                    catch (NumberFormatException e) {
                        invalid++;
                    }
                    break;
                }
                if (!found) {
                    invalid++;
                }
            }
            catch (FileNotFoundException e) {
                if (thread.isDirectory()) {
                    failed++;
                }
            }
            catch (IOException | SecurityException e) {
                failed++;
            }
        }
        if (!evidences.isEmpty()) {
            return HeuristicResult.detected(evidences);
        }
        if (invalid > 0) {
            return HeuristicResult.error("DEBUG_THREAD_TRACERPID_INVALID",
                    "Invalid or missing TracerPid in " + invalid + " thread status files");
        }
        if (failed > 0) {
            return HeuristicResult.inconclusive("Unable to inspect " + failed + " thread status files");
        }
        if (inspected == 0) {
            return HeuristicResult.inconclusive("No thread status files inspected");
        }
        return HeuristicResult.clean();
    }
}
