package com.fuad.fuadx.reflection;

import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.Method;

public class Reflection {
    private static final String TAG = "ReflectionFuadX";
    public static Method getMethod(String className, String methodName)
            throws ClassNotFoundException {
        Class<?> clazz = Class.forName(className);
        Method[] methods = clazz.getDeclaredMethods();
        for (Method method : methods) {
            Log.e(TAG, "Method: " + method.getName() + ", Class: " + className +
                    ", Method Name: " + methodName);
            if (method.getName().equals(methodName)) {
                Log.e(TAG, "Found method: " + method.getName());
                method.setAccessible(true);
                return method;
            }
        }
        return null;
    }

    public static Field getField(String className, String fieldName) throws ClassNotFoundException {
        Class<?> clazz = Class.forName(className);
        Field[] fields = clazz.getDeclaredFields();
        for (Field field : fields) {
            if (field.getName().equals(fieldName)) {
                field.setAccessible(true);
                return field;
            }
        }
        return null;
    }
}
