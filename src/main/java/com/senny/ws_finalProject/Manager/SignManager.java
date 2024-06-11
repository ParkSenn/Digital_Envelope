package com.senny.ws_finalProject.Manager;

import java.security.*;

public class SignManager {
    private static final String signAlgorithm = "SHA256withRSA";

    public static final String getSignAlgorithm() {
        return signAlgorithm;
    }
    public static byte[] createSign(PrivateKey prKey, byte[] byteData) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {

        Signature sig = Signature.getInstance(signAlgorithm);
        sig.initSign(prKey);
        sig.update(byteData);

        return sig.sign(); // byteData의 해시 값을 계산해줌
    }

    public static boolean verifySign(PublicKey publicKey, byte[] data, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance(signAlgorithm);
        sig.initVerify(publicKey);
        sig.update(data);

        return sig.verify(signature);
    }



}
