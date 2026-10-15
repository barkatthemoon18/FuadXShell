package com.fuad.fuadx.errormsgbox;

public enum ErrorCodes {
    /* Network Error Code */
    NETWORK_NO_CONN(907, "\nAl parecer no tienes conexión a Internet. Verifica tu " +
            "conexión e inténtalo nuevamente.\n\n[E907]"),

    /* Default Titles */
    DEFAULT_ERROR_ROOT_TITLE(900, "Dispositivo Modificado"),
    DEFAULT_ERROR_NO_CONN_TITLE(907, "Sin conexión a Internet"),
    DEFAULT_ERROR_PINNING_TITLE(908, "Red Insegura"),
    DEFAULT_ERROR_INTEGRITY_CONTROL_TITLE(1006, "Aplicación Modificada"),
    DEFAULT_ERROR_GENERIC_TITLE(-1000, "Error General"),

    /* Root Detection Error Codes */
    DEFAULT_ERROR_ROOT_MESSAGE(900, "\n Detectamos que el dispositivo ha sido " +
            "modificado, lo que no cumple con las normas de seguridad establecidas para su " +
            "ejecución.\n\n"),

    /* Pinning Error Codes */
    DEFAULT_ERROR_PINNING_MESSAGE(908, "\n Detectamos que estás conectado a una red " +
            "insegura. Comunícate con tu operador de Internet.\n\n[E908]"),

    /* Error on Module Loading */
    DEFAULT_ERROR_INTEGRITY_CONTROL_NOT_LOADED(1001, "Ha ocurrido un error al iniciar " +
            "la aplicación.\n\n[E1001]"),
    DEFAULT_ERROR_PINNING_NOT_LOADED(1002, "Ha ocurrido un error al iniciar la " +
            "aplicación.\n\n[E1002]"),
    DEFAULT_ERROR_ROOT_NOT_LOADED(1003, "Ha ocurrido un error al iniciar la " +
            "aplicación.\n\n[E1003]"),
    DEFAULT_ERROR_FRIDA_NOT_LOADED(1004, "Ha ocurrido un error al iniciar la " +
            "aplicación.\n\n[E1004]"),
    DEFAULT_ERROR_DEBUG_NOT_LOADED(1005, "Ha ocurrido un error al iniciar la " +
            "aplicación.\n\n[E1005]"),

    /* Integrity Control */
    DEFAULT_ERROR_INTEGRTIY_CONTROL(1006, "Se ha detectado que la aplicación se " +
            "encuentra alterada..\n\n[E1006]"),

    /* General Error */
    DEFAULT_ERROR_GENERIC_MESSAGE(-1000, "Error General. Favor intentar nuevamente"),

    /* Detections */
    FATAL_FRIDA_THREAD_DETECTED(1007, "Se ha detectado una herramienta de hooking"),
    FATAL_FRIDA_NAMED_PIPE_DETECTED(1008, "Se ha detectado una herramienta de hooking"),
    FATAL_FRIDA_LOADED_LIBRARY_DETECTED(1009, "Se ha detecado una ejecución nativa " +
            "de hooking"),
    FATAL_SSL_PINNING_ONE_CERTIFICATE(1010, "Se ha detectado un único certificado " +
            "en la cadena. Sospechoso"),
    FATAL_SSL_PINNING_WRONG_CHAIN_VALIDATION(1011, "Se ha detectado una " +
            "validación incorrecta de la cadena de certificados"),
    FATAL_DEBUG_JAVA_DEBUGGER(1012, "Se ha detectado un " +
            "debugger de Java/Android"),
    FATAL_DEBUG_NATIVE_DEBUGGER(1013, "Se ha detectado un " +
            "debugger nativo");


    private final int value;
    private final String valueStr;

    ErrorCodes(int value, String valueStr) {
        this.value = value;
        this.valueStr = valueStr;
    }

    public int getValue() {
        return value;
    }

    public String getValueStr() {
        return valueStr;
    }
}
