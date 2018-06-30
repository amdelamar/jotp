package com.amdelamar.jotp.util;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class Utils {

    private Utils() {
        // prevent instantiation
    }

    /**
     * Uses the JCE to provide the cryptographic hash. HMAC computes a Hashed Message
     * Authentication Code with the hash algorithm as a parameter.
     * 
     * @param alg
     *            algorithm (HmacSHA1, HmacSHA256, HmacSHA512)
     * @param keyBytes
     *            the bytes to use for the HMAC key
     * @param text
     *            the message or text to be authenticated
     * @return hash byte array
     * @throws NoSuchAlgorithmException if hmac sha1 is not available
     * @throws InvalidKeyException if given key  is inappropriate for this mac
     */
    public static byte[] hmac(String alg, byte[] keyBytes, byte[] text)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmac = Mac.getInstance(alg);
        SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
        hmac.init(macKey);
        return hmac.doFinal(text);
    }
}
