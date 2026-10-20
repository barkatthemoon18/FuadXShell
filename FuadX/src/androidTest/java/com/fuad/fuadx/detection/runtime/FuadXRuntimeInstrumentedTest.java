package com.fuad.fuadx.detection.runtime;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.fuad.fuadx.detection.DetectionContext;
import com.fuad.fuadx.detection.DetectionEvidence;
import com.fuad.fuadx.detection.DetectionModule;
import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.DetectionSource;
import com.fuad.fuadx.detection.policy.DetectionDecision;
import com.fuad.fuadx.detection.policy.DetectionPolicy;
import com.fuad.fuadx.detection.reporting.DetectionReporter;
import com.fuad.fuadx.module.ModuleId;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Collections;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

@RunWith(AndroidJUnit4.class)
public class FuadXRuntimeInstrumentedTest {

    private FuadXRuntime runtime;
    private DetectionReporter mockReporter;
    private DetectionPolicy mockPolicy;
    private CountDownLatch reportLatch;
    private Context appContext;

    @Before
    public void setUp() {
        appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
        reportLatch = new CountDownLatch(1);
        mockPolicy = result -> DetectionDecision.REPORT_DETECTION;
        mockReporter = (result, decision) -> reportLatch.countDown();
    }

    @After
    public void tearDown() {
        if (runtime != null) {
            runtime.close();
        }
    }

    @Test
    public void testScheduleOnceExecutesImmediately() throws InterruptedException {
        DetectionModule fakeModule = new DetectionModule() {
            @Override
            public ModuleId id() {
                return ModuleId.ROOT;
            }

            @Override
            public DetectionResult check(DetectionContext context) {
                return DetectionResult.detected(ModuleId.ROOT, Collections.singletonList(
                        new DetectionEvidence("mock", "mock", "mock", DetectionSource.ANDROID_SIDE)));
            }
        };

        runtime = new FuadXRuntime(
                appContext, 
                result -> {}, 
                mockPolicy, 
                mockReporter, 
                Collections.singletonList(fakeModule)
        );

        assertTrue("Should schedule ROOT module once", runtime.startOnce(ModuleId.ROOT));
        
        assertTrue("Module should have executed and triggered reporter", reportLatch.await(2, TimeUnit.SECONDS));
    }

    @Test(expected = IllegalArgumentException.class)
    public void testStartFailsForUnregisteredModule() {
        runtime = new FuadXRuntime(
                appContext, 
                result -> {}, 
                mockPolicy, 
                mockReporter, 
                Collections.emptyList() // No modules registered
        );

        runtime.start(ModuleId.FRIDA, 1000);
    }

    @Test(expected = IllegalStateException.class)
    public void testConstructorFailsIfDuplicateModulesProvided() {
        DetectionModule mod1 = new DetectionModule() {
            @Override
            public ModuleId id() { return ModuleId.DEBUG; }
            @Override
            public DetectionResult check(DetectionContext context) { return DetectionResult.clean(ModuleId.DEBUG); }
        };

        DetectionModule mod2 = new DetectionModule() {
            @Override
            public ModuleId id() { return ModuleId.DEBUG; } // Same ID
            @Override
            public DetectionResult check(DetectionContext context) { return DetectionResult.clean(ModuleId.DEBUG); }
        };

        java.util.List<DetectionModule> duplicateModules = new java.util.ArrayList<>();
        duplicateModules.add(mod1);
        duplicateModules.add(mod2);

        try (FuadXRuntime failingRuntime = new FuadXRuntime(appContext, result -> {}, mockPolicy, mockReporter, duplicateModules)) {
            fail("Should throw IllegalStateException");
        }
    }

    @Test(expected = IllegalStateException.class)
    public void testOperationsFailAfterClose() {
        DetectionModule fakeModule = new DetectionModule() {
            @Override
            public ModuleId id() { return ModuleId.ROOT; }
            @Override
            public DetectionResult check(DetectionContext context) { return DetectionResult.clean(ModuleId.ROOT); }
        };

        runtime = new FuadXRuntime(appContext, result -> {}, mockPolicy, mockReporter, Collections.singletonList(fakeModule));
        
        runtime.close();
        
        // This should throw IllegalStateException because ensureOpen() is called
        runtime.startOnce(ModuleId.ROOT);
    }

    @Test
    public void testStopModuleReturnsFalseIfClosed() {
        DetectionModule fakeModule = new DetectionModule() {
            @Override
            public ModuleId id() { return ModuleId.ROOT; }
            @Override
            public DetectionResult check(DetectionContext context) { return DetectionResult.clean(ModuleId.ROOT); }
        };

        runtime = new FuadXRuntime(appContext, result -> {}, mockPolicy, mockReporter, Collections.singletonList(fakeModule));
        
        runtime.close();
        
        // stop() explicitly checks closed and returns false instead of throwing
        assertFalse(runtime.stop(ModuleId.ROOT));
    }
}