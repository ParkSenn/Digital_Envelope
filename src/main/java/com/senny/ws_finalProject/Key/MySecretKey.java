package com.senny.ws_finalProject.Key;

import lombok.Getter;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

@Getter
public class MySecretKey {
    private static final String keyAlgorithm = "AES"; // For secretKey
    private KeyGenerator keyGen;
    private SecretKey secretKey;

    public static MySecretKey getSecretKeyInstance(int keylength) throws NoSuchAlgorithmException {
        MySecretKey rslt = new MySecretKey();

        rslt.keyGen = KeyGenerator.getInstance(keyAlgorithm);
        rslt.keyGen.init(keylength);

        return rslt;
    }

    public void createSecretKey() {
        this.secretKey = this.keyGen.generateKey();
    }

    public void saveSecretKey(String userId) throws IOException {
        saveKey(this.secretKey, userId + "_secret.key");
    }

    public void saveKey(Key key, String fname) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(fname);
             ObjectOutputStream os = new ObjectOutputStream(fos)) {
            os.writeObject(key);
        }
    }

    public static SecretKey readSecretKey(String keyFname) {
        try (FileInputStream fis = new FileInputStream(keyFname);
             ObjectInputStream os = new ObjectInputStream(fis)) {
            return (SecretKey) os.readObject();
        } catch (IOException | ClassNotFoundException e) {
            System.out.println("키 불러오기 실패");
            System.out.println(e.getMessage());
            return null;
        }
    }
}
