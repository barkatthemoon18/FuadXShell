package com.fuad.fuadx.detection.runtime;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class ProcessScopeTest {

    @Test
    public void testClassifyMainProcess() {
        assertEquals(ProcessScope.MAIN, ProcessScope.classify("com.fuad.app", "com.fuad.app"));
    }

    @Test
    public void testClassifySecondaryProcess() {
        assertEquals(ProcessScope.SECONDARY, ProcessScope.classify("com.fuad.app:auth", "com.fuad.app"));
        assertEquals(ProcessScope.SECONDARY, ProcessScope.classify("com.fuad.app:remote", "com.fuad.app"));
    }

    @Test
    public void testClassifyUnknownWhenActualIsEmpty() {
        assertEquals(ProcessScope.UNKNOWN, ProcessScope.classify("", "com.fuad.app"));
        assertEquals(ProcessScope.UNKNOWN, ProcessScope.classify(null, "com.fuad.app"));
    }

    @Test
    public void testClassifyUnknownWhenExpectedIsEmpty() {
        assertEquals(ProcessScope.UNKNOWN, ProcessScope.classify("com.fuad.app", ""));
        assertEquals(ProcessScope.UNKNOWN, ProcessScope.classify("com.fuad.app", null));
    }

    @Test
    public void testClassifyUnknownWhenBothAreEmpty() {
        assertEquals(ProcessScope.UNKNOWN, ProcessScope.classify("", ""));
        assertEquals(ProcessScope.UNKNOWN, ProcessScope.classify(null, null));
    }
}