package com.fuad.fuadx.logger;

import com.fuad.fuadx.util.AndroidUtil;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;

import java.util.Map;

public class FuadXLogEntry {
    public String timestamp;
    public String message;
    public String tag;
    public LogLevel level;
    public Map<String, Object> metadata;

    public FuadXLogEntry(String tag, String message, LogLevel level) {
        this.timestamp = AndroidUtil.generateTimestamp();
        this.level = level;
        this.tag = tag;
        this.message = message;
    }

    public FuadXLogEntry(String tag, String message, LogLevel level, Map<String, Object> metadata) {
        this(tag, message, level);
        this.metadata = metadata;
    }

    public JsonObject asJsonOrdered() {
        JsonObject jsonObject = new JsonObject();

        jsonObject.addProperty("timestamp", timestamp);
        jsonObject.addProperty("level", level.getLevel());
        jsonObject.addProperty("tag", tag);
        jsonObject.addProperty("message", message);
        if (metadata != null) {
            JsonObject metadataJson = new GsonBuilder().disableHtmlEscaping().create()
                    .toJsonTree(metadata).getAsJsonObject();
            jsonObject.add("metadata", metadataJson);
        }
        return jsonObject;
    }
}
