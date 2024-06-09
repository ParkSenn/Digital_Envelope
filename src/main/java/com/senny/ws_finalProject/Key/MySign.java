package com.senny.ws_finalProject.Key;

import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;

public class MySign {
    public static byte[] createSign(PrivateKey prKey, byte[] byteData) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeyException {
        String signAlgorithm = "SHA256withRSA";

        Signature sig = Signature.getInstance(signAlgorithm);
        sig.initSign(prKey);
        sig.update(byteData);

        return sig.sign(); // byteData의 해시 값을 계산해줌
    }

    public static void saveSign(byte[] sign, String fname) throws IOException {
        try (FileOutputStream os = new FileOutputStream(fname)) {
            try {
                os.write(sign);
                System.out.println("서명을 파일에 저장했습니다.");
            } catch (IOException e) {
                System.out.println("서명을 파일에 저장하는 걸 실패했습니.");
//                e.printStackTrace();
            }
        }
    }

    public static boolean verifySign(PublicKey publicKey, byte[] data, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        String signAlgorithm = "SHA256withRSA";

        Signature sig = Signature.getInstance(signAlgorithm);
        sig.initVerify(publicKey);
        sig.update(data);

        return sig.verify(signature);
    }



}
