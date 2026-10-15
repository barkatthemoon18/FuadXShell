# FuadXShell

Este es un proyecto de Android que integra componentes nativos (C/C++) mediante JNI/CMake.

## Estructura del Proyecto

El proyecto está compuesto por los siguientes módulos principales:
- **`app`**: Módulo de la aplicación principal de Android.
- **`FuadX`**: Biblioteca de Android (Android Library).
- **`FuadXShell`**: Módulo que contiene la lógica de bajo nivel y código nativo escrito en C (incluyendo operaciones de desempaquetado en `unpack.c`).

## Entorno de Desarrollo

Para compilar y ejecutar este proyecto, necesitas:
- **Android Studio** (versión reciente recomendada).
- **Android NDK** (Native Development Kit) y **CMake** instalados desde el SDK Manager de Android Studio.

## Notas sobre el Repositorio

Se ha configurado un archivo `.gitignore` estricto para evitar subir archivos innecesarios al repositorio, tales como:
- Carpetas de compilación (`build/`, `.cxx/`, `.externalNativeBuild/`).
- Archivos temporales de Android Studio (`.idea/`, `.gradle/`, `*.iml`).
- Archivos locales y de credenciales (`local.properties`, keystores).
