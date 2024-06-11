package com.senny.ws_finalProject.exceptions;

public class EncryptionException extends Exception{
    public EncryptionException(String message) {
        super(message);
    }

    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
}
