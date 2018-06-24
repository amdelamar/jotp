package com.amdelamar.jotp.type;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Time based OTP class implements OTPInterface
 * 
 * @author kamranzafar, amdelamar
 * @see <a href="https://tools.ietf.org/html/rfc6238">https://tools.ietf.org/html/rfc6238</a>
 * @since 1.0.0
 */
public class TOTP implements OTPInterface {

    /**
     * HmacSHA1, HmacSHA256, HmacSHA512
     */
    private static final String HMACSHA1_ALGORITHM = "HmacSHA1";
    private static final String LABEL = "totp";

    @Override
    public String getLabel() {
        return LABEL;
    }

    /**
     * Create a one-time-password with the given key, base, and digits.
     * 
     * @param secret
     *            The secret. Shhhhhh!
     * @param base
     *            The offset. (TOTP base is time from UTC rounded to the half-second)
     * @param digits
     *            The length of the code (Commonly '6')
     * @return code
     * @throws NoSuchAlgorithmException when HMAC is not available on this jvm
     * @throws InvalidKeyException when secret is invalid
     * @see <a href="https://tools.ietf.org/html/rfc6238">https://tools.ietf.org/html/rfc6238</a>
     */
    public String create(String secret, String base, int digits) throws InvalidKeyException, NoSuchAlgorithmException {
        return generateTotp(secret, base, digits, HMACSHA1_ALGORITHM);
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
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     */
    protected static byte[] hmac(String alg, byte[] keyBytes, byte[] text)
            throws NoSuchAlgorithmException, InvalidKeyException {
        Mac hmac = Mac.getInstance(alg);
        SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
        hmac.init(macKey);
        return hmac.doFinal(text);
    }

    /**
     * Converts a Hex based string to byte[]
     * 
     * @param hex
     *            the HEX string
     * @return byte array
     */
    protected static byte[] hexStringToBytes(String hex) {
        // Adding one byte to get the right conversion
        // Values starting with "0" can be converted
        byte[] bArray = new BigInteger("10" + hex, 16).toByteArray();

        // Copy all the REAL bytes, not the "first"
        byte[] ret = new byte[bArray.length - 1];
        for (int i = 0; i < ret.length; i++) {
            ret[i] = bArray[i + 1];
        }
        return ret;
    }

    /**
     * Generates a TOTP value for the given set of parameters.
     * 
     * @param key
     *            the shared secret, HEX encoded
     * @param time
     *            a value that reflects a time
     * @param returnDigits
     *            number of digits to return
     * @param crypto
     *            the crypto function to use
     * @return numeric String in base 10 that includes digits
     * @throws NoSuchAlgorithmException 
     * @throws InvalidKeyException 
     */
    protected static String generateTotp(String key, String time, int digits, String crypto)
            throws InvalidKeyException, NoSuchAlgorithmException {
        // Using the counter
        // First 8 bytes are for the movingFactor
        // Compliant with base RFC 4226 (HOTP)
        while (time.length() < 16) {
            time = "0" + time;
        }

        // Get the HEX in a Byte[]
        byte[] msg = hexStringToBytes(time);
        byte[] k = hexStringToBytes(key);

        byte[] hash = hmac(crypto, k, msg);

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;

        int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);

        int otp = binary % ((int) Math.pow(10, digits));

        String result = Integer.toString(otp);
        while (result.length() < digits) {
            result = "0" + result;
        }
        return result;
    }
}
