package com.fuad.fuadx.detection.runtime;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import android.content.Context;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import com.fuad.fuadx.detection.DetectionContext;
import com.fuad.fuadx.detection.DetectionModule;
import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.module.ModuleId;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

@RunWith(AndroidJUnit4.class)
public class DetectionSchedulerInstrumentedTest {

    private DetectionScheduler scheduler;
    private Context appContext;

    @Before
    public void setUp() {
        appContext = InstrumentationRegistry.getInstrumentation().getTargetContext();
        scheduler = new DetectionScheduler(result -> {});
    }

    @After
    public void tearDown() throws Exception {
        if (scheduler != null) {
            scheduler.close();
        }
    }

    @Test
    public void testPublicScheduleAPI() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        DetectionModule module = new DetectionModule() {
            @Override
            public ModuleId id() { return ModuleId.FRIDA; }

            @Override
            public DetectionResult check(DetectionContext ctx) {
                latch.countDown();
                return DetectionResult.clean(ModuleId.FRIDA);
            }
        };

        DetectionContext ctx = new DetectionContext(appContext);

        assertTrue(scheduler.schedule(module, ctx, 100));

        assertTrue(latch.await(2, TimeUnit.SECONDS));
    }

    @Test
    public void testPublicScheduleOnceAPI() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(1);
        DetectionModule module = new DetectionModule() {
            @Override
            public ModuleId id() { return ModuleId.ROOT; }

            @Override
            public DetectionResult check(DetectionContext ctx) {
                latch.countDown();
                return DetectionResult.clean(ModuleId.ROOT);
            }
        };

        DetectionContext ctx = new DetectionContext(appContext);

        assertTrue(scheduler.scheduleOnce(module, ctx));

        assertTrue(latch.await(2, TimeUnit.SECONDS));
    }
}