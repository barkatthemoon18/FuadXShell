package com.fuad.fuadx.detection.debug;

import com.fuad.fuadx.heuristic.HeuristicResult;
import com.fuad.fuadx.probe.ProbeDefinition;

import org.junit.Test;

import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class DebugDetectionModuleTest {
    private final ExecutorService executor = Executors.newFixedThreadPool(2);

    @Test(expected = NullPointerException.class)
    public void testCheckRejectsNullContext() {
        DebugDetectionModule module = new DebugDetectionModule(Arrays.asList(
                probe("tracerPid"), probe("jdwpThreads"), probe("threadTracerPid"),
                probe("tracedState"), probe("wchan"), probe("javaDebugger")),
                executor, 1000);
        module.check(null);
        executor.shutdownNow();
    }

    private static ProbeDefinition probe(String name) {
        return new ProbeDefinition(name, name.toUpperCase() + "_FAILED", HeuristicResult::clean);
    }
}