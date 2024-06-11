package com.senny.ws_finalProject.exceptions;

public class SignatureVerificationException extends Exception {
    public SignatureVerificationException(String message) {
        super(message);
    }

    public SignatureVerificationException(String message, Throwable cause) {
        super(message, cause);
    }
}
