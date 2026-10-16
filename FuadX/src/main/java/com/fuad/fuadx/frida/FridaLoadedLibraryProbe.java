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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class FridaLoadedLibraryProbe {
    private static final Pattern MAP_ENTRY = Pattern.compile("^[0-9a-fA-F]+-[0-9a-fA-F]+\\s+"
            + "[r-][w-][x-][ps]\\s+"
            + "[0-9a-fA-F]+\\s+"
            + "[0-9a-fA-F]+:[0-9a-fA-F]+\\s+"
            + "\\d+(?:\\s+(.*))?$");
    private static final String[] INDICATORS = {
            Constants.FRIDA_AGENT,
            Constants.FRIDA_GADGET,
            Constants.FRIDA_SERVER,
            Constants.LINJECTOR
    };
    private final File mapsFile;

    public FridaLoadedLibraryProbe() {
        this(new File(Constants.PATH_PROC_MAPS));
    }

    FridaLoadedLibraryProbe(File mapsFile) {
        this.mapsFile = Objects.requireNonNull(mapsFile);
    }

    public HeuristicResult scan() {
        Map<String, DetectionEvidence> findings = new LinkedHashMap<>();
        Matcher matcher;
        String line;
        String mappedPath;
        String fileName;
        String key;
        int validEntries = 0;
        int malformedEntries = 0;

        try (BufferedReader reader = new BufferedReader(new FileReader(mapsFile))) {
            while ((line = reader.readLine()) != null) {
                matcher = MAP_ENTRY.matcher(line);
                if (!matcher.matches()) {
                    if (!line.trim().isEmpty()) {
                        malformedEntries++;
                    }
                    continue;
                }
                validEntries++;
                mappedPath = matcher.group(1);
                if (mappedPath == null || mappedPath.isEmpty()) {
                    continue;
                }
                fileName = mappedFileName(mappedPath);
                for (String indicator : INDICATORS) {
                    if (!fileName.contains(indicator.toLowerCase(Locale.ROOT))) {
                        continue;
                    }
                    key = indicator + ":" + mappedPath;
                    findings.putIfAbsent(key, new DetectionEvidence("FridaLoadedLibraries",
                            "scanProcSelfMaps", "Mapped indicator (" + indicator + "): " +
                            mappedPath, DetectionSource.ANDROID_SIDE));
                }
            }
        }
        catch (FileNotFoundException | SecurityException e) {
            return HeuristicResult.inconclusive("Process memory maps are unavailable");
        }
        catch (IOException e) {
            if (!findings.isEmpty()) {
                return detected(findings);
            }
            return HeuristicResult.error("FRIDA_MAPS_READ_FAILED", "Unable to complete memory map inspection");
        }
        if (!findings.isEmpty()) {
            return detected(findings);
        }
        if (validEntries == 0) {
            return HeuristicResult.inconclusive("No valid memory mappings were inspected");
        }
        if (malformedEntries > 0) {
            return HeuristicResult.inconclusive("Some memory mapping entries were malformed");
        }
        return HeuristicResult.clean();
    }


    private static HeuristicResult detected(Map<String, DetectionEvidence> findings) {
        return HeuristicResult.detected(new ArrayList<>(findings.values()));
    }

    private static String mappedFileName(String mappedPath) {
        String normalized = mappedPath;
        int separator;

        if (normalized.endsWith(" (deleted)")) {
            normalized = normalized.substring(0, normalized.length() - " (deleted)".length());
        }
        separator = normalized.lastIndexOf('/');
        return normalized.substring(separator + 1).toLowerCase(Locale.ROOT);
    }
}
