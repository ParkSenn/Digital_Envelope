package com.senny.ws_finalProject.util;

import com.senny.ws_finalProject.Manager.KeyPairManager;
import com.senny.ws_finalProject.Manager.SecretKeyManager;
import com.senny.ws_finalProject.Manager.SignManager;
import com.senny.ws_finalProject.dto.Profile;
import com.senny.ws_finalProject.exceptions.DecryptionException;
import com.senny.ws_finalProject.exceptions.FileReadException;
import com.senny.ws_finalProject.exceptions.SignatureVerificationException;

import javax.crypto.*;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class AdminDecryptionUtil { //AES, RSA
    public static Profile decryptProfileEnvelope(String userId) throws DecryptionException, SignatureVerificationException, FileReadException {
        try {
            // Admin의 개인 키 읽기
            PrivateKey adminPrKey = KeyPairManager.readPrKey("admin_private.key");

            // 전자봉투에서 AES 비밀 키 복호화
            Cipher rsaCipher = Cipher.getInstance(KeyPairManager.getKeyAlgorithm());
            rsaCipher.init(Cipher.UNWRAP_MODE, adminPrKey);
            byte[] wrappedSecretKey = readEncryptedData(userId, "secret");
            SecretKey secretKey = (SecretKey) rsaCipher.unwrap(wrappedSecretKey, SecretKeyManager.getKeyAlgorithm(), Cipher.SECRET_KEY);

            // 암호화된 프로필 데이터 읽기
            byte[] encryptedData = readEncryptedData(userId, "profile");

            // AES 비밀 키로 암호화된 데이터 복호화
            Cipher aesCipher = Cipher.getInstance(SecretKeyManager.getKeyAlgorithm());
            aesCipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedData = aesCipher.doFinal(encryptedData);

            // 복호화된 프로필 데이터
            byte[] profileBytes = decryptedData;

            // 서명 및 공개 키 읽기
            byte[] encryptedSignature = readEncryptedData(userId, "signature");
            byte[] encryptedPublicKey = readEncryptedData(userId, "public");

            // 전자서명 및 공개 키 복호화
            byte[] signature = decryptData(encryptedSignature, secretKey);
            PublicKey publicKey = decryptPublicKey(encryptedPublicKey, secretKey);

            // 전자서명 검증
            boolean isVerified = SignManager.verifySign(publicKey, profileBytes, signature);
            if (isVerified) {
                System.out.println("복호화 성공");
                return deserializeProfile(profileBytes);
            } else {
                throw new SignatureVerificationException("전자서명 검증 실패!");
            }
        }
        catch (Exception e) {
            throw new DecryptionException("복호화 실패: " + e.getMessage(), e);
        }
    }

    private static Profile deserializeProfile(byte[] profileBytes) throws DecryptionException {
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(profileBytes))) {
            return (Profile) ois.readObject();
        } catch (IOException | ClassNotFoundException e) {
            throw new DecryptionException("프로필 역직렬화 실패: " + e.getMessage(), e);
        }
    }

    private static byte[] readEncryptedData(String userId, String file)  throws FileReadException {
        String fname = userId;

        switch (file) {
            case "profile" -> fname += "_profile.dat";
            case "secret" -> fname += "_secret.key";
            case "signature" -> fname += "_signature.dat";
            case "public" -> fname += "_public.key";
        }

        try (FileInputStream fis = new FileInputStream(fname)) {
            return fis.readAllBytes();
        } catch (IOException e) {
            throw new FileReadException("파일 읽기 실패: " + e.getMessage(), e);
        }
    }

    private static byte[] decryptData(byte[] encryptedData, SecretKey secretKey) throws DecryptionException {
        try {
            Cipher aesCipher = Cipher.getInstance(SecretKeyManager.getKeyAlgorithm());
            aesCipher.init(Cipher.DECRYPT_MODE, secretKey);
            return aesCipher.doFinal(encryptedData);
        } catch (Exception e) {
            throw new DecryptionException("데이터 복호화 실패: " + e.getMessage(), e);
        }
    }

    private static PublicKey decryptPublicKey(byte[] encryptedPublicKey, SecretKey secretKey) throws DecryptionException {
        try {
            Cipher aesCipher = Cipher.getInstance(SecretKeyManager.getKeyAlgorithm());
            aesCipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedPublicKeyBytes = aesCipher.doFinal(encryptedPublicKey);

            KeyFactory keyFactory = KeyFactory.getInstance(KeyPairManager.getKeyAlgorithm());
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decryptedPublicKeyBytes);
            return keyFactory.generatePublic(publicKeySpec);
        } catch (Exception e) {
            throw new DecryptionException("공개키 복호화 실패: " + e.getMessage(), e);
        }
    }
}


