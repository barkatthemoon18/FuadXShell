package com.fuad.fuadx.detection;

import java.util.Objects;

public final class DetectionEvidence {
    private final String heuristic;
    private final String method;
    private final String details;
    private final DetectionSource source;

    public DetectionEvidence(String heuristic, String method, String details, DetectionSource source) {
        this.heuristic = Objects.requireNonNull(heuristic);
        this.method = Objects.requireNonNull(method);
        this.details = Objects.requireNonNull(details);
        this.source = Objects.requireNonNull(source);
    }

    public String getHeuristic() {
        return heuristic;
    }

    public String getMethod() {
        return method;
    }

    public String getDetails() {
        return details;
    }

    public DetectionSource getSource() {
        return source;
    }
}