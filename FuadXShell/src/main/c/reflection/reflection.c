#include "reflection.h"

void *getJNIClass(JNIEnv *env, const char *className)
{
    void *classObj = (*env)->FindClass(env, className);
    if (!classObj)
    {
        FUADXSHELL_LOG_W("Class %s is null. Checking exception...", className);
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
            FUADXSHELL_LOG_E("Exception while loading class: %s", className);
            return NULL;
        }
    }
    return classObj;
}

void *getJNIObject(JNIEnv *env, void *class, void *classMethodId)
{
    void *object = (*env)->CallObjectMethod(env, class, classMethodId);
    if (!object)
    {
        FUADXSHELL_LOG_W("Object is null. Checking exception...");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
            FUADXSHELL_LOG_E("Exception while loading object");
            return NULL;
        }
    }
    return object;
}

void *getJNIMethodID(JNIEnv *env, void *class, const char *methodIdStr, const char *methodSignature)
{
    void *methodId = (*env)->GetMethodID(env, class, methodIdStr, methodSignature);
    if (!methodId)
    {
        FUADXSHELL_LOG_W("Method %s is null. Checking exception...", methodIdStr);
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
            FUADXSHELL_LOG_E("Exception while loading method: %s", methodIdStr);
            return NULL;
        }
    }
    return methodId;
}

void *getJNIStaticMethodID(JNIEnv *env, void *class, const char *methodName, const char *methodSignature)
{
    void *methodId = (*env)->GetStaticMethodID(env, class, methodName, methodSignature);
    if (!methodId)
    {
        FUADXSHELL_LOG_W("Method %s is null. Checking exception...", methodName);
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
            FUADXSHELL_LOG_E("Exception while loading method: %s", methodName);
            return NULL;
        }
    }
    return methodId;
}

void *getJNIField(JNIEnv *env, void *classField, void *fieldID)
{
    void *field = (*env)->GetObjectField(env, classField, fieldID);
    if (!field)
    {
        FUADXSHELL_LOG_W("Field is null. Checking exception...");
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
            FUADXSHELL_LOG_E("Exception while loading field");
            return NULL;
        }
    }
    return field;
}

void *getJNIFieldID(JNIEnv *env, void *class, const char *fieldName, const char *fieldSignature)
{
    void *fieldId = (*env)->GetFieldID(env, class, fieldName, fieldSignature);
    if (!fieldId)
    {
        FUADXSHELL_LOG_W("Field %s is null. Checking exception...", fieldName);
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionDescribe(env);
            (*env)->ExceptionClear(env);
            FUADXSHELL_LOG_E("Exception while loading field: %s", fieldName);
            return NULL;
        }
    }
    return fieldId;
}

void *getDeclaredJNIField(JNIEnv *env, void *instanceObject, void *nameStringObject)
{
    void *_instanceCls = NULL;
    void *_classCls = NULL;
    void *_fieldCls = NULL;
    void *_classObj = NULL;
    void *_fieldObj = NULL;
    void *_getDeclaredFieldMethodId = NULL;
    void *_getClassMethodId = NULL;
    void *_setAccessibleMethodId = NULL;
    void *_getSuperclassMethodId = NULL;

    _instanceCls = (*env)->GetObjectClass(env, instanceObject);
    _getClassMethodId = (*env)->GetMethodID(env, _instanceCls, "getClass", "()Ljava/lang/Class;");
    if (!_getClassMethodId && (*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionClear(env);
        (*env)->FatalError(env, "UNEXPECTED: Application found a condition that could not be performed [E1100]");
    }
    _classObj = (*env)->CallObjectMethod(env, instanceObject, _getClassMethodId);
    if ((*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionClear(env);
        (*env)->FatalError(env, "UNEXPECTED: Application found a condition that could not be performed [E1101]");
    }
    _classCls = (*env)->FindClass(env, "java/lang/Class");
    if (!_classCls && (*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionClear(env);
        (*env)->FatalError(env, "UNEXPECTED: Application found a condition that could not be performed [E1102]");
    }
    _fieldCls = (*env)->FindClass(env, "java/lang/reflect/Field");
    if (!_fieldCls && (*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionClear(env);
        (*env)->FatalError(env, "UNEXPECTED: Application found a condition that could not be performed [E1103]");
    }
    _getDeclaredFieldMethodId = (*env)->GetMethodID(env, _classCls, "getDeclaredField", "(Ljava/lang/String;)Ljava/lang/reflect/Field;");
    if (!_getDeclaredFieldMethodId && (*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionClear(env);
        (*env)->FatalError(env, "UNEXPECTED: Application found a condition that could not be performed [E1104]");
    }
    _setAccessibleMethodId = (*env)->GetMethodID(env, _fieldCls, "setAccessible", "(Z)V");
    if (!_setAccessibleMethodId && (*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionClear(env);
        (*env)->FatalError(env, "UNEXPECTED: Application found a condition that could not be performed [E1105]");
    }
    _getSuperclassMethodId = (*env)->GetMethodID(env, _classCls, "getSuperclass", "()Ljava/lang/Class;");
    if (!_getSuperclassMethodId && (*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionClear(env);
        (*env)->FatalError(env, "UNEXPECTED: Application found a condition that could not be performed [E1106]");
    }

    /* Test class and superclass */
    while (_classObj)
    {
        _fieldObj = (*env)->CallObjectMethod(env, _classObj, _getDeclaredFieldMethodId, nameStringObject);
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionClear(env);
            FUADXSHELL_LOG_E("Error while getting field: %s in class", (*env)->GetStringUTFChars(env, nameStringObject, NULL));
            _classObj = (*env)->CallObjectMethod(env, _classObj, _getSuperclassMethodId);
        }
        else
        {
            /* Got the superclass */
            (*env)->CallVoidMethod(env, _fieldObj, _setAccessibleMethodId, 1);
            FUADXSHELL_LOG_E("Field was found and set as accessible");
            return _fieldObj;
        }
    }
    FUADXSHELL_LOG_E("Field %s couldn't be found", (*env)->GetStringUTFChars(env, nameStringObject, NULL));
    return NULL; /* Neither the class or superclasses found the field */
}

void *getDeclaredJNIMethod(JNIEnv *env, void *instanceObject, void *nameStringObject, void *params)
{
    void *_instanceCls = NULL;
    void *_classCls = NULL;
    void *_methodCls = NULL;
    void *_classObj = NULL;
    void *_methodObj = NULL;
    void *_getDeclaredMethodMethodId = NULL;
    void *_getClassMethodId = NULL;
    void *_setAccessibleMethodId = NULL;
    void *_getSuperclassMethodId = NULL;

    _instanceCls = (*env)->GetObjectClass(env, instanceObject);
    _getClassMethodId = (*env)->GetMethodID(env, _instanceCls, "getClass", "()Ljava/lang/Class;");
    if (!_getClassMethodId && (*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionClear(env);
        (*env)->FatalError(env, "UNEXPECTED: Application found a condition that could not be performed [E300]");
    }
    _classObj = (*env)->CallObjectMethod(env, instanceObject, _getClassMethodId);
    if ((*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionClear(env);
        (*env)->FatalError(env, "UNEXPECTED: Application found a condition that could not be performed [E301]");
    }
    _classCls = (*env)->FindClass(env, "java/lang/Class");
    if (!_classCls && (*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionClear(env);
        (*env)->FatalError(env, "UNEXPECTED: Application found a condition that could not be performed [E302]");
    }
    _methodCls = (*env)->FindClass(env, "java/lang/reflect/Method");
    if (!_methodCls && (*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionClear(env);
        (*env)->FatalError(env, "UNEXPECTED: Application found a condition that could not be performed [E303]");
    }
    _getDeclaredMethodMethodId = (*env)->GetMethodID(env, _classCls, "getDeclaredMethod", "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;");
    if (!_getDeclaredMethodMethodId && (*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionClear(env);
        (*env)->FatalError(env, "UNEXPECTED: Application found a condition that could not be performed [E304]");
    }
    _setAccessibleMethodId = (*env)->GetMethodID(env, _methodCls, "setAccessible", "(Z)V");
    if (!_setAccessibleMethodId && (*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionClear(env);
        (*env)->FatalError(env, "UNEXPECTED: Application found a condition that could not be performed [E305]");
    }
    _getSuperclassMethodId = (*env)->GetMethodID(env, _classCls, "getSuperclass", "()Ljava/lang/Class;");
    if (!_getSuperclassMethodId && (*env)->ExceptionCheck(env))
    {
        (*env)->ExceptionClear(env);
        (*env)->FatalError(env, "UNEXPECTED: Application found a condition that could not be performed [E306]");
    }

    /* Test class and superclass */
    while (_classObj)
    {
        _methodObj = (*env)->CallObjectMethod(env, _classObj, _getDeclaredMethodMethodId, nameStringObject, params);
        if ((*env)->ExceptionCheck(env))
        {
            (*env)->ExceptionClear(env);
            FUADXSHELL_LOG_E("Error while getting method: %s in class", (*env)->GetStringUTFChars(env, nameStringObject, NULL));
            _classObj = (*env)->CallObjectMethod(env, _classObj, _getSuperclassMethodId);
        }
        else
        {
            /* Got the superclass */
            (*env)->CallVoidMethod(env, _methodObj, _setAccessibleMethodId, 1);
            FUADXSHELL_LOG_E("Method was found and set as accessible");
            return _methodObj;
        }
    }
    FUADXSHELL_LOG_E("Method %s couldn't be found", (*env)->GetStringUTFChars(env, nameStringObject, NULL));
    return NULL; /* Neither the class or superclasses found the method */
}