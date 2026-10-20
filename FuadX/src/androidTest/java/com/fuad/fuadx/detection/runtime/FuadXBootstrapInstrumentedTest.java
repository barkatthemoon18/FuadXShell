package com.fuad.fuadx.detection.runtime;

import static org.junit.Assert.assertEquals;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class FuadXBootstrapInstrumentedTest {

    @Test
    public void testBootstrapLifecycle() throws InterruptedException {
        // Context of the app under test.
        Context appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();

        // Create bootstrap
        FuadXBootstrap bootstrap = new FuadXBootstrap(appContext);
        
        // Initial state
        assertEquals(FuadXBootstrap.State.NEW, bootstrap.getState());

        // Start initialization
        bootstrap.start();

        // Wait a reasonable amount of time for the background thread to finish initialization.
        // It's going to schedule Frida which might take a few milliseconds.
        Thread.sleep(1000); // 1 second

        // After successfully starting, the state should be RUNNING.
        assertEquals(FuadXBootstrap.State.RUNNING, bootstrap.getState());

        // Close the bootstrap
        bootstrap.close();

        // After closing, the state should be CLOSED.
        assertEquals(FuadXBootstrap.State.CLOSED, bootstrap.getState());
    }
}