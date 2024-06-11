package com.senny.ws_finalProject.Manager;

import lombok.Getter;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

@Getter
public class SecretKeyManager {
    private static final String keyAlgorithm = "AES"; // For secretKey
    private KeyGenerator keyGen;
    private SecretKey secretKey;

    public static SecretKeyManager getSecretKeyInstance(int keylength) throws NoSuchAlgorithmException {
        SecretKeyManager rslt = new SecretKeyManager();

        rslt.keyGen = KeyGenerator.getInstance(keyAlgorithm);
        rslt.keyGen.init(keylength);

        return rslt;
    }

    public void createSecretKey() {
        this.secretKey = this.keyGen.generateKey();
    }

    public void saveKey(Key key, String fname) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(fname);
             ObjectOutputStream os = new ObjectOutputStream(fos)) {
            os.writeObject(key);
        }
    }

}
