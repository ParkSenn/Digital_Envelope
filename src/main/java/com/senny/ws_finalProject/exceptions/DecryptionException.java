package com.senny.ws_finalProject.exceptions;

public class DecryptionException extends Exception {
    public DecryptionException(String message) {
        super(message);
    }

    public DecryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
