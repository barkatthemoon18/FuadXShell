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
        
        try {
            // Initial state
            assertEquals(FuadXBootstrap.State.NEW, bootstrap.getState());

            // Start initialization
            bootstrap.start();

            // Wait until the state transitions to RUNNING or we timeout
            long timeoutMillis = 3000;
            long intervalMillis = 100;
            long start = System.currentTimeMillis();
            
            while (bootstrap.getState() == FuadXBootstrap.State.STARTING || bootstrap.getState() == FuadXBootstrap.State.NEW) {
                if (System.currentTimeMillis() - start >= timeoutMillis) {
                    break;
                }
                Thread.sleep(intervalMillis);
            }

            // After successfully starting (or timing out), the state should be RUNNING.
            assertEquals("Bootstrap did not reach RUNNING state within " + timeoutMillis + "ms", 
                    FuadXBootstrap.State.RUNNING, bootstrap.getState());
        } finally {
            // Close the bootstrap securely
            bootstrap.close();
            
            // After closing, the state should be CLOSED.
            assertEquals(FuadXBootstrap.State.CLOSED, bootstrap.getState());
        }
    }
}