package com.fuad.fuadx.detection.reporting;

import com.fuad.fuadx.detection.DetectionResult;
import com.fuad.fuadx.detection.policy.DetectionDecision;

import java.util.Objects;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

public final class AsyncDetectionReporter  implements DetectionReporter, AutoCloseable {
    private static final class Event {
        final DetectionResult result;
        final DetectionDecision decision;

        Event(DetectionResult result, DetectionDecision decision) {
            this.result = Objects.requireNonNull(result);
            this.decision = Objects.requireNonNull(decision);
        }
    }

    private final Object lock = new Object();
    private final ArrayBlockingQueue<Event> queue;
    private final DetectionReporter downstream;
    private final Consumer<DetectionResult> overflowHandler;
    private final Consumer<RuntimeException> failureHandler;
    private final Thread worker;
    private final AtomicLong droppedDiagnostics = new AtomicLong();
    private final AtomicLong undeliveredDetections = new AtomicLong();
    private final AtomicLong deliveryFailures = new AtomicLong();
    private final AtomicLong notificationFailures = new AtomicLong();
    private volatile boolean accepting = true;

    public AsyncDetectionReporter(int capacity, DetectionReporter downstream,
                                  Consumer<DetectionResult> overflowHandler,
                                  Consumer<RuntimeException> failureHandler) {
        if (capacity < 1) {
            throw new IllegalArgumentException("Queue capacity must be positive");
        }
        this.queue = new ArrayBlockingQueue<>(capacity);
        this.downstream = Objects.requireNonNull(downstream, "downstream");
        this.overflowHandler = Objects.requireNonNull(overflowHandler, "overflowHandler");
        this.failureHandler = Objects.requireNonNull(failureHandler, "failureHandler");
        worker = new Thread(this::drain, "FuadX-Reporter-Worker");
        worker.setDaemon(true);
        worker.start();
    }

    @Override
    public void report(DetectionResult result, DetectionDecision decision) {
        Event incoming;
        boolean overflow;

        Objects.requireNonNull(result, "result");
        Objects.requireNonNull(decision, "decision");
        if (decision == DetectionDecision.CONTINUE) {
            return;
        }
        overflow = false;
        synchronized (lock) {
            if (!accepting) {
                if (decision == DetectionDecision.REPORT_DETECTION) {
                    undeliveredDetections.incrementAndGet();
                    overflow = true;
                }
                else {
                    droppedDiagnostics.incrementAndGet();
                }
            }
            else {
                incoming = new Event(result, decision);
                if (queue.offer(incoming)) {
                    return;
                }
                if (decision == DetectionDecision.REPORT_DIAGNOSTIC) {
                    droppedDiagnostics.incrementAndGet();
                    return;
                }
                for (Event queued : queue) {
                    if (queued.decision == DetectionDecision.REPORT_DIAGNOSTIC && queue.remove(queued)) {
                        droppedDiagnostics.incrementAndGet();
                        break;
                    }
                }
                if (queue.offer(incoming)) {
                    return;
                }
                undeliveredDetections.incrementAndGet();
                overflow = true;
            }
        }
        if (overflow) {
            notifyOverflow(result);
        }
    }

    @Override
    public void close() {
        synchronized (lock) {
            accepting = false;
        }
    }

    public long getDroppedDiagnostics() {
        return droppedDiagnostics.get();
    }

    public long getUndeliveredDetections() {
        return undeliveredDetections.get();
    }

    public long getDeliveryFailures() {
        return deliveryFailures.get();
    }

    public long getNotificationFailures() {
        return notificationFailures.get();
    }

    public int getPendingEvents() {
        return queue.size();
    }

    public boolean awaitTermination(long timeout, TimeUnit unit) throws InterruptedException {
        Objects.requireNonNull(unit, "unit");

        if (timeout <= 0) {
            throw new IllegalArgumentException("Timeout must be positive");
        }
        worker.join(Math.max(1L, unit.toMillis(timeout)));
        return !worker.isAlive();
    }

    private void drain() {
        Event event;

        while (accepting || !queue.isEmpty()) {
            try {
                event = queue.poll(100, TimeUnit.MILLISECONDS);
            }
            catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
            if (event == null) {
                continue;
            }
            try {
                downstream.report(event.result, event.decision);
            }
            catch (RuntimeException e) {
                deliveryFailures.incrementAndGet();
                notifyFailure(e);
                if (event.decision == DetectionDecision.REPORT_DETECTION) {
                    undeliveredDetections.incrementAndGet();
                    notifyOverflow(event.result);
                }
            }
        }
    }

    private void notifyOverflow(DetectionResult result) {
        try {
            overflowHandler.accept(result);
        }
        catch (RuntimeException e) {
            notificationFailures.incrementAndGet();
            notifyFailure(e);
        }
    }

    private void notifyFailure(RuntimeException error) {
        try {
            failureHandler.accept(error);
        }
        catch (RuntimeException ignored) {
            notificationFailures.incrementAndGet();
        }
    }
}
