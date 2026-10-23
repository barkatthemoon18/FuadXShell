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

public final class DebugTracedStateProbe {
    private final File taskDirectory;

    public DebugTracedStateProbe() {
        this(new File(Constants.PATH_PROC_SELF_TASK));
    }

    public DebugTracedStateProbe(File taskDirectory) {
        this.taskDirectory = Objects.requireNonNull(taskDirectory, "taskDirectory");
        ;
    }

    public HeuristicResult scan() {
        List<DetectionEvidence> evidences = new ArrayList<>();
        File[] threads;
        File statFile;
        String line;
        int signalStopped = 0;
        int inspected = 0;
        int failed = 0;
        int invalid = 0;
        int close;
        char state;

        if (!taskDirectory.isDirectory()) {
            return HeuristicResult.inconclusive("Thread directory unavailable");
        }
        threads = taskDirectory.listFiles();
        if (threads == null) {
            return HeuristicResult.error("DEBUG_TRACED_STATE_ENUM_FAILED", "Unable to enumerate process threads");
        }
        for (File thread : threads) {
            if (!thread.isDirectory()) {
                continue;
            }
            statFile = new File(thread, "stat");
            try (BufferedReader reader = new BufferedReader(new FileReader(statFile))) {
                line = reader.readLine();
                if (line == null) {
                    invalid++;
                    continue;
                }
                close = line.lastIndexOf(')');
                if (close < 0 || close + 2 >= line.length() || line.charAt(close + 1) != ' ') {
                    invalid++;
                    continue;
                }
                state = line.charAt(close + 2);
                inspected++;
                if (state == 't') {
                    evidences.add(new DetectionEvidence("TracedThreadState",
                            "readThreadStat", "tid=" + thread.getName() + ", stat=t",
                            DetectionSource.ANDROID_SIDE));
                } else if (state == 'T') {
                    signalStopped++;
                }
            } catch (FileNotFoundException e) {
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
            return HeuristicResult.error("DEBUG_TRACED_STATE_INVALID",
                    "Malformed stat data in: " + invalid + " thread files");
        }
        if (failed > 0) {
            return HeuristicResult.inconclusive("Unable to inspect " + failed + " thread stat files");
        }
        if (signalStopped > 0) {
            return HeuristicResult.inconclusive(signalStopped + " threads are signal-stopped");
        }
        if (inspected == 0) {
            return HeuristicResult.inconclusive("No thread stat files inspected");
        }
        return HeuristicResult.clean();
    }
}