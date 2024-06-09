package com.senny.ws_finalProject.util;

import com.senny.ws_finalProject.Key.MyKeyPair;
import com.senny.ws_finalProject.Key.MySecretKey;
import com.senny.ws_finalProject.Key.MySign;
import com.senny.ws_finalProject.dto.Profile;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;

public class ProfileEncryptionUtil {
    public static void saveProfileWithEnvelope(Profile profile, String userId) throws Exception {
        // AES 비밀 키 생성
        MySecretKey mySecretKey = MySecretKey.getSecretKeyInstance(256);
        mySecretKey.createSecretKey();

        // 사용자 RSA 키 생성 및 저장
        MyKeyPair myKeyPair = MyKeyPair.getInstance(2048);
        myKeyPair.createKeys();
        myKeyPair.saveKeys(userId);

        // 프로필 객체를 직렬화하여 바이트 배열로 변환
        byte[] profileBytes;
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(profile);
            profileBytes = baos.toByteArray();
        }

        // 사용자 전자서명 생성 및 비밀 키로 암호화
        byte[] signature = MySign.createSign(myKeyPair.getPrivateKey(), profileBytes);
        Cipher aesCipher = Cipher.getInstance("AES");
        aesCipher.init(Cipher.ENCRYPT_MODE, mySecretKey.getSecretKey());
        byte[] encryptedSignature = aesCipher.doFinal(signature);

        // 프로필 데이터를 비밀 키로 암호화
        byte[] encryptedProfileData = aesCipher.doFinal(profileBytes);

        // 사용자 공개 키를 비밀 키로 암호화
        byte[] publicKeyBytes = myKeyPair.getPublicKey().getEncoded();
        byte[] encryptedPublicKey = aesCipher.doFinal(publicKeyBytes);

        // Admin 공개 키를 이용해 AES 비밀 키를 암호화 (전자봉투 생성)
        PublicKey adminPbKey = MyKeyPair.readPbKey("admin_public.key");
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.WRAP_MODE, adminPbKey);
        byte[] encryptedSecretKey = rsaCipher.wrap(mySecretKey.getSecretKey());

        // 각 데이터를 별도 파일에 저장
        saveToFile(userId + "_profile.dat", encryptedProfileData);
        saveToFile(userId + "_signature.dat", encryptedSignature);
        saveToFile(userId + "_public.key", encryptedPublicKey);
        saveToFile(userId + "_secret.key", encryptedSecretKey);

        System.out.println("암호화 성공");
    }

    private static void saveToFile(String fileName, byte[] data) throws Exception {
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            fos.write(data);
        }
    }
}
