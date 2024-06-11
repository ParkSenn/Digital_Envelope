package com.senny.ws_finalProject.Manager;

import java.security.*;

public class SignManager {
    public static byte[] createSign(PrivateKey prKey, byte[] byteData) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeyException {
        String signAlgorithm = "SHA256withRSA";

        Signature sig = Signature.getInstance(signAlgorithm);
        sig.initSign(prKey);
        sig.update(byteData);

        return sig.sign(); // byteData의 해시 값을 계산해줌
    }

    public static boolean verifySign(PublicKey publicKey, byte[] data, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        String signAlgorithm = "SHA256withRSA";

        Signature sig = Signature.getInstance(signAlgorithm);
        sig.initVerify(publicKey);
        sig.update(data);

        return sig.verify(signature);
    }



}
