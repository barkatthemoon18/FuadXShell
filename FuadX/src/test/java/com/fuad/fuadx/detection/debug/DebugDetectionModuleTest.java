package com.fuad.fuadx.detection.debug;

import com.fuad.fuadx.heuristic.HeuristicResult;

import org.junit.Test;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class DebugDetectionModuleTest {
    private final ExecutorService executor = Executors.newFixedThreadPool(2);

    @Test(expected = NullPointerException.class)
    public void testCheckRejectsNullContext() {
        DebugDetectionModule module = new DebugDetectionModule(HeuristicResult::clean,
                HeuristicResult::clean, executor, 1000);
        module.check(null);
    }
}