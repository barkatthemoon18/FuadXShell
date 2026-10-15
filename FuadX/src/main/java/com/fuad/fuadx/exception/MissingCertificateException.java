package com.fuad.fuadx.exception;

public class MissingCertificateException extends RuntimeException {
    public MissingCertificateException() {
        super();
    }

    public MissingCertificateException(String message) {
        super(message);
    }

    public MissingCertificateException(String message, Throwable cause) {
        super(message, cause);
    }

    public MissingCertificateException(Throwable cause) {
        super(cause);
    }

    protected MissingCertificateException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
