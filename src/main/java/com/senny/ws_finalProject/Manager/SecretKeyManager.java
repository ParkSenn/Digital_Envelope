package com.senny.ws_finalProject.Manager;

import lombok.Getter;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;

@Getter
public class SecretKeyManager {
    private static final String keyAlgorithm = "AES"; // For secretKey
    private KeyGenerator keyGen;
    private SecretKey secretKey;

    public static final String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public static SecretKeyManager getSecretKeyInstance(int keylength) throws NoSuchAlgorithmException {
        SecretKeyManager rslt = new SecretKeyManager();

        rslt.keyGen = KeyGenerator.getInstance(keyAlgorithm);
        rslt.keyGen.init(keylength);

        return rslt;
    }

    public void createSecretKey() {
        this.secretKey = this.keyGen.generateKey();
    }

}
