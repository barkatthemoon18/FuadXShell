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
import java.util.Locale;
import java.util.Objects;

public final class DebugWchanProbe {
    private final File taskDirectory;

    public DebugWchanProbe() {
        this(new File(Constants.PATH_PROC_SELF_TASK));
    }

    public DebugWchanProbe(File taskDirectory) {
        this.taskDirectory = Objects.requireNonNull(taskDirectory, "taskDirectory");
    }

    public HeuristicResult scan() {
        List<DetectionEvidence> evidences = new ArrayList<>();
        File[] threads;
        File wchanFile;
        String line;
        String symbol;
        int inspected = 0;
        int failed = 0;
        int invalid = 0;
        int unknown = 0;
        int close;
        char state;

        if (!taskDirectory.isDirectory()) {
            return HeuristicResult.inconclusive("Thread directory unavailable");
        }
        threads = taskDirectory.listFiles();
        if (threads == null) {
            return HeuristicResult.error("DEBUG_WCHAN_ENUM_FAILED", "Unable to enumerate process threads");
        }
        for (File thread : threads) {
            if (!thread.isDirectory()) {
                continue;
            }
            wchanFile = new File(thread, "wchan");
            try (BufferedReader reader = new BufferedReader(new FileReader(wchanFile))) {
                line = reader.readLine();
                if (line == null || line.trim().isEmpty()) {
                    unknown++;
                    continue;
                }
                symbol = line.trim().toLowerCase(Locale.ROOT);
                if ("0".equals(symbol) || "-".equals(symbol)) {
                    unknown++;
                    continue;
                }
                inspected++;
                if (symbol.contains(Constants.PTRACE_STOP)) {
                    evidences.add(new DetectionEvidence("PtraceStopWchan",
                            "readThreadWchan", "tid=" + thread.getName() + ", wchan=" + symbol,
                            DetectionSource.ANDROID_SIDE));
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
        if (failed > 0) {
            return HeuristicResult.inconclusive("Unable to inspect " + failed + " thread wait channels");
        }
        if (unknown > 0) {
            return HeuristicResult.inconclusive("Wait channel unavailable for " + unknown + " threads");
        }
        if (inspected == 0) {
            return HeuristicResult.inconclusive("No readable wait channels");
        }
        return HeuristicResult.clean();
    }
}
