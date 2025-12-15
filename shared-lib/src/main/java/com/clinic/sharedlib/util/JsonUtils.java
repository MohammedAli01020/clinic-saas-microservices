package com.clinic.sharedlib.util;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Tiny JSON helper — services can reuse or override.
 */
public final class JsonUtils {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private JsonUtils(){}

    public static String toJson(Object obj){
        try { return MAPPER.writeValueAsString(obj); }
        catch(Exception ex) { throw new RuntimeException(ex); }
    }

    public static <T> T fromJson(String json, Class<T> cls){
        try { return MAPPER.readValue(json, cls); }
        catch(Exception ex) { throw new RuntimeException(ex); }
    }
}