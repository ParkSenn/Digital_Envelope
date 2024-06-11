package com.senny.ws_finalProject.util;

import com.senny.ws_finalProject.Manager.KeyPairManager;
import com.senny.ws_finalProject.Manager.SecretKeyManager;
import com.senny.ws_finalProject.Manager.SignManager;
import com.senny.ws_finalProject.dto.Profile;
import com.senny.ws_finalProject.exceptions.EncryptionException;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

public class ProfileEncryptionUtil {
    public static void saveProfileWithEnvelope(Profile profile, String userId) throws EncryptionException {
        try {
            // AES 비밀 키 생성
            SecretKeyManager secretKeyManager = SecretKeyManager.getSecretKeyInstance(256);
            secretKeyManager.createSecretKey();

            // 사용자 RSA 키 생성 및 저장
            KeyPairManager keyPairManager = KeyPairManager.getInstance(2048);
            keyPairManager.createKeys();
            keyPairManager.saveKeys(userId);

            // 프로필 객체를 직렬화하여 바이트 배열로 변환
            byte[] profileBytes;
            try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
                 ObjectOutputStream oos = new ObjectOutputStream(baos)) {
                oos.writeObject(profile);
                profileBytes = baos.toByteArray();
            }

            // 사용자 전자서명 생성 및 비밀 키로 암호화
            byte[] signature = SignManager.createSign(keyPairManager.getPrivateKey(), profileBytes);
            Cipher aesCipher = Cipher.getInstance(SecretKeyManager.getKeyAlgorithm());
            aesCipher.init(Cipher.ENCRYPT_MODE, secretKeyManager.getSecretKey());
            byte[] encryptedSignature = aesCipher.doFinal(signature);

            // 프로필 데이터를 비밀 키로 암호화
            byte[] encryptedProfileData = aesCipher.doFinal(profileBytes);

            // 사용자 공개 키를 비밀 키로 암호화
            byte[] publicKeyBytes = keyPairManager.getPublicKey().getEncoded();
            byte[] encryptedPublicKey = aesCipher.doFinal(publicKeyBytes);

            // Admin 공개 키를 이용해 AES 비밀 키를 암호화 (전자봉투 생성)
            PublicKey adminPbKey = KeyPairManager.readPbKey("admin_public.key");
            Cipher rsaCipher = Cipher.getInstance(KeyPairManager.getKeyAlgorithm());
            rsaCipher.init(Cipher.WRAP_MODE, adminPbKey);
            byte[] encryptedSecretKey = rsaCipher.wrap(secretKeyManager.getSecretKey());

            // 각 데이터를 별도 파일에 저장
            saveToFile(userId + "_profile.dat", encryptedProfileData);
            saveToFile(userId + "_signature.dat", encryptedSignature);
            saveToFile(userId + "_public.key", encryptedPublicKey);
            saveToFile(userId + "_secret.key", encryptedSecretKey);

            System.out.println("암호화 성공");
        } catch (Exception e) {
            throw new EncryptionException("암호화 과정 중 오류 발생", e);
        }
    }

    private static void saveToFile(String fileName, byte[] data) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(data);
        } catch (IOException e) {
            throw new IOException("파일 저장 중 오류");
        }
    }
}
