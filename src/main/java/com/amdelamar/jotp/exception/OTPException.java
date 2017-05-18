package com.amdelamar.jotp.exception;

public class OTPException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public OTPException(String message) {
        super(message);
    }

    public OTPException(Throwable cause) {
        super(cause);
    }

    public OTPException(String message, Throwable cause) {
        super(message, cause);
    }

}