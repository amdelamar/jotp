package com.amdelamar.jotp.type;

import java.lang.reflect.UndeclaredThrowableException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Hmac based OTP class implements OTPInterface
 * 
 * @author kamranzafar, amdelamar
 * @see https://tools.ietf.org/html/rfc4226
 * @since 1.0.0
 */
public class HOTP implements OTPInterface {

    private static final int TRUNCATE_OFFSET = 0;
    private static final boolean CHECKSUM = false;

    /**
     * HmacSHA1, HmacSHA256, HmacSHA512
     */
    private static final String HMACSHA1_ALGORITHM = "HmacSHA1";

    private static final String LABEL = "hotp";

    /**
     * These are used to calculate the check-sum digits. [0 1 2 3 4 5 6 7 8 9]
     */
    private static final int[] doubleDigits = { 0, 2, 4, 6, 8, 1, 3, 5, 7, 9 };

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
     *            The offset. (HOTP is a counter incremented by each use)
     * @param digits
     *            The length of the code (Commonly '6')
     * @return code
     * @throws BadOperationException
     * @see https://tools.ietf.org/html/rfc4226
     */
    public String create(String secret, String base, int digits) {
        try {
            return generateHotp(secret.getBytes(), Long.parseLong(base), digits, CHECKSUM, TRUNCATE_OFFSET, HMACSHA1_ALGORITHM);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * This method uses the JCE to provide the crypto algorithm. HMAC computes a Hashed Message
     * Authentication Code with the crypto hash algorithm as a parameter.
     * 
     * @param crypto
     *            the crypto algorithm (HmacSHA1, HmacSHA256, HmacSHA512)
     * @param keyBytes
     *            the bytes to use for the HMAC key
     * @param text
     *            the message or text to be authenticated
     */
    private static byte[] hmac(String crypto, byte[] keyBytes, byte[] text) {
        try {
            Mac hmac = Mac.getInstance(crypto);
            SecretKeySpec macKey = new SecretKeySpec(keyBytes, "RAW");
            hmac.init(macKey);
            return hmac.doFinal(text);
        } catch (GeneralSecurityException gse) {
            throw new UndeclaredThrowableException(gse);
        }
    }

    /**
     * Calculates the checksum using the credit card algorithm. This algorithm has the advantage
     * that it detects any single mistyped digit and any single transposition of adjacent digits.
     * 
     * @param num
     *            the number to calculate the checksum for
     * @param digits
     *            number of significant places in the number
     * @return the checksum of num
     */
    private static int calcChecksum(long num, int digits) {
        boolean doubleDigit = true;
        int total = 0;
        while (0 < digits--) {
            int digit = (int) (num % 10);
            num /= 10;
            if (doubleDigit) {
                digit = doubleDigits[digit];
            }
            total += digit;
            doubleDigit = !doubleDigit;
        }
        int result = total % 10;
        if (result > 0) {
            result = 10 - result;
        }
        return result;
    }

    /**
     * This method generates an OTP value for the given set of parameters.
     * 
     * @param secret
     *            Shhhhh.
     * @param movingFactor
     *            the counter, time, or other value
     * @param digits
     *            length of the code
     * @param addChecksum
     *            a flag that indicates if the checksum digit should be appened to the OTP
     * @param truncationOffset
     *            the offset into the MAC result to begin truncation. If this value is out of the
     *            range of 0 ... 15, then dynamic truncation will be used. Dynamic truncation is
     *            when the last 4 bits of the last byte of the MAC are used to determine the start
     *            offset.
     * @param crypto
     *            the crypto function to use
     * @return An OTP code.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private static String generateHotp(byte[] secret,
            long movingFactor,
            int digits,
            boolean addChecksum,
            int truncationOffset,
            String crypto) throws NoSuchAlgorithmException, InvalidKeyException {
        // put movingFactor value into text byte array
        byte[] text = new byte[8];
        for (int i = text.length - 1; i >= 0; i--) {
            text[i] = (byte) (movingFactor & 0xff);
            movingFactor >>= 8;
        }

        // compute hmac hash
        byte[] hash = hmac(crypto, secret, text);

        // put selected bytes into result int
        int offset = hash[hash.length - 1] & 0xf;
        if ((0 <= truncationOffset) && (truncationOffset < (hash.length - 4))) {
            offset = truncationOffset;
        }
        int binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);

        int otp = binary % ((int) Math.pow(10, digits));
        if (addChecksum) {
            otp = (otp * 10) + calcChecksum(otp, digits);
        }
        String result = Integer.toString(otp);
        int digit = addChecksum ? (digits + 1) : digits;
        while (result.length() < digit) {
            result = "0" + result;
        }
        return result;
    }
}
