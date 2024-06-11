package com.senny.ws_finalProject.Manager;

import lombok.Getter;

import java.io.*;
import java.security.*;

@Getter
public class KeyPairManager {
    private static final String keyAlgorithm = "RSA"; // For pb,pr key

    private KeyPairGenerator keyGen;
    private KeyPair pair;

    private PrivateKey privateKey;
    private PublicKey publicKey;

    public static final String getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public static KeyPairManager getInstance(int keylength) throws NoSuchAlgorithmException {
        KeyPairManager rslt = new KeyPairManager();

        rslt.keyGen = KeyPairGenerator.getInstance(keyAlgorithm);
        rslt.keyGen.initialize(keylength);

        return rslt;
    }

    public void createKeys() {
        this.pair = this.keyGen.generateKeyPair();
        this.privateKey = pair.getPrivate();
        this.publicKey = pair.getPublic();
    }

    public void saveKeys(String userId) throws IOException {
        saveKey(this.publicKey, userId + "_public.key");
        saveKey(this.privateKey, userId + "_private.key");
    }

    public void saveKey(Key key, String fname) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(fname);
             ObjectOutputStream os = new ObjectOutputStream(fos)) {
            os.writeObject(key);
        }
    }

    public static PrivateKey readPrKey(String keyFname) {
        try (FileInputStream fis = new FileInputStream(keyFname);
             ObjectInputStream os = new ObjectInputStream(fis)) {
            return (PrivateKey) os.readObject();
        } catch (IOException | ClassNotFoundException e) {
            System.out.println("키 불러오기 실패");
            System.out.println(e.getMessage());
            return null;
        }
    }

    public static PublicKey readPbKey(String keyFname) {
        try (FileInputStream fis = new FileInputStream(keyFname);
             ObjectInputStream os = new ObjectInputStream(fis)) {
            return (PublicKey) os.readObject();
        } catch (IOException | ClassNotFoundException e) {
            System.out.println("키 불러오기 실패");
            System.out.println(e.getMessage());
            return null;
        }
    }

}
