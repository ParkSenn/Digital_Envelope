package com.senny.ws_finalProject.Manager;

import java.security.*;

public class SignManager {
    private static final String signAlgorithm = "SHA256withRSA";

    public static byte[] createSign(PrivateKey prKey, byte[] byteData) {
        byte[] signature = null;
        try {
            Signature sig = Signature.getInstance(signAlgorithm);
            sig.initSign(prKey);
            sig.update(byteData);
            signature = sig.sign();
        }  catch (InvalidKeyException | SignatureException e) {
            e.printStackTrace();
            signature = new byte[0];
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        return signature;
    }

    public static boolean verifySign(PublicKey publicKey, byte[] data, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance(signAlgorithm);
        sig.initVerify(publicKey);
        sig.update(data);

        return sig.verify(signature);
    }



}
