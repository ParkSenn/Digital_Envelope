package com.senny.ws_finalProject.util;

import com.senny.ws_finalProject.Key.MyKeyPair;
import com.senny.ws_finalProject.Key.MySign;
import com.senny.ws_finalProject.dto.Profile;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class AdminDecryptionUtil {
    public static Profile decryptProfileEnvelope(String userId) throws Exception {
        // Admin의 개인 키 읽기
        PrivateKey adminPrKey = MyKeyPair.readPrKey("admin_private.key");

        // 전자봉투에서 AES 비밀 키 복호화
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.UNWRAP_MODE, adminPrKey);
        byte[] wrappedSecretKey = readEncryptedSecretKey(userId);
        SecretKey secretKey = (SecretKey) rsaCipher.unwrap(wrappedSecretKey, "AES", Cipher.SECRET_KEY);

        // 암호화된 프로필 데이터 읽기
        byte[] encryptedData = readEncryptedProfileData(userId);

        // AES 비밀 키로 암호화된 데이터 복호화
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedData = aesCipher.doFinal(encryptedData);

        // 복호화된 프로필 데이터
        byte[] profileBytes = decryptedData;

        // 서명 및 공개 키 읽기
        byte[] encryptedSignature = readEncryptedSignature(userId);
        byte[] encryptedPublicKey = readEncryptedPublicKey(userId);

        // 전자서명 및 공개 키 복호화
        byte[] signature = decryptData(encryptedSignature, secretKey);
        PublicKey publicKey = decryptPublicKey(encryptedPublicKey, secretKey);

        // 전자서명 검증
        boolean isVerified = MySign.verifySign(publicKey, profileBytes, signature);
        if (isVerified) {
            System.out.println("복호화 성공");
            return deserializeProfile(profileBytes);
        } else {
            throw new Exception("전자서명 검증 실패!");
        }
    }

    private static Profile deserializeProfile(byte[] profileBytes) throws Exception {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(profileBytes))) {
            return (Profile) ois.readObject();
        }
    }

    private static byte[] readEncryptedSecretKey(String userId) throws Exception {
        try (FileInputStream fis = new FileInputStream(userId + "_secret.key")) {
            return fis.readAllBytes();
        }
    }

    private static byte[] readEncryptedProfileData(String userId) throws Exception {
        try (FileInputStream fis = new FileInputStream(userId + "_profile.dat")) {
            return fis.readAllBytes();
        }
    }

    private static byte[] readEncryptedSignature(String userId) throws Exception {
        try (FileInputStream fis = new FileInputStream(userId + "_signature.dat")) {
            return fis.readAllBytes();
        }
    }

    private static byte[] readEncryptedPublicKey(String userId) throws Exception {
        try (FileInputStream fis = new FileInputStream(userId + "_public.key")) {
            return fis.readAllBytes();
        }
    }

    private static byte[] decryptData(byte[] encryptedData, SecretKey secretKey) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, secretKey);
        return aesCipher.doFinal(encryptedData);
    }

    private static PublicKey decryptPublicKey(byte[] encryptedPublicKey, SecretKey secretKey) throws Exception {
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decryptedPublicKeyBytes = aesCipher.doFinal(encryptedPublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decryptedPublicKeyBytes);
        return keyFactory.generatePublic(publicKeySpec);
    }
}
