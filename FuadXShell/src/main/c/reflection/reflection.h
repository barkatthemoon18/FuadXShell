#ifndef REFLECTION_H
#define REFLECTION_H

/* Default includes */
#include <jni.h>

/* Defs */
#include "defs.h"

/* JNI function declarations */
ATTRIBUTES(section(".text_ext"), always_inline, used) void *getJNIClass(JNIEnv *, const char *);
ATTRIBUTES(section(".text_ext"), always_inline, used) void *getJNIObject(JNIEnv *, void *, void *);
ATTRIBUTES(section(".text_ext"), always_inline, used) void *getJNIMethodID(JNIEnv *, void *, const char *, const char *);
ATTRIBUTES(section(".text_ext"), always_inline, used) void *getJNIStaticMethodID(JNIEnv *, void *, const char *, const char *);
ATTRIBUTES(section(".text_ext"), always_inline, used) void *getJNIField(JNIEnv *, void *, void *);
ATTRIBUTES(section(".text_ext"), always_inline, used) void *getJNIFieldID(JNIEnv *, void *, const char *, const char *);
ATTRIBUTES(section(".text_ext"), always_inline, used) void *getDeclaredJNIField(JNIEnv *, void *, void *);
ATTRIBUTES(section(".text_ext"), always_inline, used) void *getDeclaredJNIMethod(JNIEnv *, void *, void *, void *);

#endif /* REFLECTION_H */
