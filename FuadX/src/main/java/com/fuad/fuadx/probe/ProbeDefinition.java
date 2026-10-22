package com.fuad.fuadx.probe;

import com.fuad.fuadx.heuristic.HeuristicResult;

import java.util.Objects;
import java.util.function.Supplier;

public final class ProbeDefinition {
    private final String name;
    private final String errorCode;
    private final Supplier<HeuristicResult> heuristic;

    public ProbeDefinition(String name, String errorCode, Supplier<HeuristicResult> heuristic) {
        this.name = requireText(name, "name");
        this.errorCode = requireText(errorCode, "errorCode");
        this.heuristic = Objects.requireNonNull(heuristic, "heuristic");
    }

    public String getName() {
        return name;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public Supplier<HeuristicResult> getHeuristic() {
        return heuristic;
    }

    private static String requireText(String value, String field) {
        Objects.requireNonNull(value, field);
        if (value.trim().isEmpty()) {
            throw new IllegalArgumentException(field + " cannot be blank");
        }
        return value;
    }
}
