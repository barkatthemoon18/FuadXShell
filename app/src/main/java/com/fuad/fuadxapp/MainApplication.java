package com.fuad.fuadxapp;

import android.app.Application;
import android.content.Context;
import android.content.res.AssetManager;
import android.os.Build;
import android.util.Log;

import java.io.File;
import java.io.InputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

import dalvik.system.DexClassLoader;

public class MainApplication extends Application {
    private static final String TAG = "FuadXApp";
    public static Application app;

    private Field getFieldObject(Object instance, String name) throws Exception {
        Field field;

        Class<?> clazz = instance.getClass();
        while (clazz != null) {
            try {
                field = clazz.getDeclaredField(name);
                field.setAccessible(true);
                return field;
            }
            catch (NoSuchFieldException e) {
                Log.e(TAG, "Field not found: " + name + " in class " + clazz.getName(), e);
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchFieldException("Error while getting field: " + name + ". Not found in: " + instance.getClass());
    }

    private Method getMethodObject(Object instance, String name, Class<?>... parameterTypes) throws Exception {
        Method method;

        Class<?> clazz = instance.getClass();
        while (clazz != null) {
            try {
                method = clazz.getDeclaredMethod(name, parameterTypes);
                method.setAccessible(true);
                return method;
            }
            catch (NoSuchMethodException e) {
                Log.e(TAG, "Method not found: " + name + " in class " + clazz.getName(), e);
                clazz = clazz.getSuperclass();
            }
        }
        throw new NoSuchMethodException("Error while getting method: " + name + ". Not found in: " + instance.getClass());
    }

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        app = this;
        System.loadLibrary("fuadxshell");
        Log.e(TAG, "Loaded successfully");
    }

    @Override
    public void onCreate() {
        Field pathListField;
        Object pathListObject;
        Field dexElementsField;
        Object[] dexElementsObject;
        Method makeDexElementsMethod;
        ArrayList<IOException> suppressedExceptionsArray;
        Object[] addElements;
        Object[] newElements;
        List<File> dexFiles = new ArrayList<>();

        super.onCreate();
        /* try {
            AssetManager assetManager = getBaseContext().getAssets();
            InputStream stream = assetManager.open("classesPrueba.dex", AssetManager.ACCESS_BUFFER);
            Log.e(TAG, "Asset classesPrueba.dex opened successfully");
            File dexFile = new File(getFilesDir(), "classesPrueba.dex");
            dexFile.createNewFile();
            Log.e(TAG, "Dex file created at: " + dexFile.getAbsolutePath());
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                Files.write(dexFile.toPath(), stream.readAllBytes());
            }
            dexFile.setWritable(false);
            dexFiles.add(dexFile);
            Log.e(TAG, "Dex file written successfully");
            stream.close();
            /* pathListField = getFieldObject(getBaseContext().getClassLoader(), "pathList");
            pathListObject = pathListField.get(getBaseContext().getClassLoader());
            dexElementsField = getFieldObject(pathListObject, "dexElements");
            dexElementsObject = (Object[]) dexElementsField.get(pathListObject);
            makeDexElementsMethod = getMethodObject(pathListObject, "makeDexElements", List.class, File.class, List.class, ClassLoader.class);
            suppressedExceptionsArray = new ArrayList<>();
            addElements = (Object[]) makeDexElementsMethod.invoke(pathListObject, dexFiles, getDir("outdex", 0), suppressedExceptionsArray, getClassLoader());
            newElements = (Object[]) Array.newInstance(dexElementsObject.getClass().getComponentType(), dexElementsObject.length, dexElementsObject.length + addElements.length);
            System.arraycopy(dexElementsObject, 0, newElements[0], 0, dexElementsObject.length);
            System.arraycopy(addElements, 0, newElements[0], dexElementsObject.length, addElements.length);
            dexElementsField.set(pathListObject, newElements[0]);
            Log.e(TAG, "Dex elements updated successfully");
        }
        catch (Exception e) {
            Log.e(TAG, "Error while loading dex file: " + e.getMessage(), e);
            throw new RuntimeException("Failed to load dex file", e);
        } */
    }
}
