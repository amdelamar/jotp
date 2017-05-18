package com.amdelamar.jotp;

import java.io.IOException;
import java.nio.ByteBuffer;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;

import com.amdelamar.jotp.exception.BadOperationException;
import com.amdelamar.jotp.exception.OTPException;
import com.amdelamar.jotp.type.HOTP;
import com.amdelamar.jotp.type.TOTP;

/**
 * OTP (One Time Password) utility in Java. To enable two-factor authentication (2FA) using
 * HMAC-based) or Time-based algorithms.
 * 
 * @author amdelamar
 * @see https://github.com/amdelamar/jotp
 */
public class OTP {

    // Algorithms
    public static final String TOTP = "totp";
    public static final String HOTP = "hotp";

    public static final int BYTES = 20; // 160 bit

    /**
     * Generate a random string using the characters provided, with the specified length.
     * 
     * @param characters
     *            A set of possible characters to be chosen.
     * @param length
     *            default 20
     * @return secure random string
     */
    public static String random(String characters, int length) {
        if (length < 1) {
            length = BYTES;
        }
        java.security.SecureRandom random = new java.security.SecureRandom();
        char[] text = new char[length];
        for (int i = 0; i < length; i++) {
            text[i] = characters.charAt(random.nextInt(characters.length()));
        }
        return new String(text);
    }
    
    /**
     * Generate a random string in Base32, with the specified length.
     * 
     * @param length
     *            default 20
     * @return secure random string
     */
    public static String randomBase32(int length) {
        if (length < 1) {
            length = BYTES;
        }
        byte[] bytes = new byte[length];
        java.security.SecureRandom random = new java.security.SecureRandom();
        random.nextBytes(bytes);

        return new Base32().encodeToString(bytes);
    }

    /**
     * A quick method to get Unix Time rounded down to the nearest 30 seconds.
     * 
     * @return String Hex time
     * @throws IOException
     *             Error when generating Unix time.
     */
    public static String timeInHex() throws IOException {
        long time = (long) Math
                .floor(Math.round(((double) System.currentTimeMillis()) / 1000.0) / 30L);
        byte[] longBytes = ByteBuffer.allocate(Long.SIZE / Byte.SIZE).putLong(time).array();
        return Hex.encodeHexString(longBytes);
    }

    /**
     * Create a one-time-password with the given key, base, digits, and OTP.Type.
     * 
     * @param secret
     *            The secret. Shhhhhh!
     * @param base
     *            The offset. (e.g. TOTP base is time from UTC rounded to the half-second while HOTP
     *            is a counter)
     * @param digits
     *            The length of the code (Commonly '6')
     * @param type
     *            TOTP or HOTP
     * @return code
     * @throws BadOperationException
     *             Error when Type is not recognized.
     * @see https://tools.ietf.org/html/rfc4226
     * @see https://tools.ietf.org/html/rfc6238
     */
    public static String create(String secret, String base, int digits, String type)
            throws BadOperationException {

        // validate
        validateParameters(secret, base, digits, type);
        
        // convert Base32 secret to Hex
        byte[] bytes = new Base32().decode(secret);
        String key = Hex.encodeHexString(bytes);

        if (type.equalsIgnoreCase(HOTP)) {
            HOTP hotp = new HOTP();
            return hotp.create(key, base, digits);
        } else {
            TOTP totp = new TOTP();
            return totp.create(key, base, digits);
        }
    }

    /**
     * Returns true if the code is valid for the Hmac-based or Time-based OTP of the secret.
     * 
     * For Hmac-based the 'base' is a counter, like 1,2,3. For Time-based the 'base' is Unix-time
     * rounded down to the nearest 30 seconds via "getTimeInHex()"
     * 
     * @param secret
     *            Shhhhh. (Base32)
     * @param base
     *            The base or counter.
     * @param code
     *            An OTP code to check.
     * @param digits
     *            Length of code (Commonly '6')
     * @param type
     *            TOTP or HOTP
     * @return true if valid
     * @throws OTPException
     *             Error when comparing codes.
     * @throws BadOperationException
     *             Error when parameters invalid.
     * @see https://tools.ietf.org/html/rfc4226
     * @see https://tools.ietf.org/html/rfc6238
     */
    public static boolean verify(String secret, String base, String code, int digits, String type)
            throws OTPException, BadOperationException {

        // validate
        validateParameters(secret, base, digits, type);
        if (code == null || code.isEmpty()) {
            throw new BadOperationException("Code cannot be null or empty.");
        }
        if (code.length() != digits) {
            // code length must match digits
            return false;
        }

        try {
            // convert Base32 secret to Hex
            byte[] bytes = new Base32().decode(secret);
            String key = Hex.encodeHexString(bytes);

            // generate code to compare
            String ncode = null;
            if (type.equalsIgnoreCase(HOTP)) {
                HOTP hotp = new HOTP();
                ncode = hotp.create(key, base, digits);
            } else {
                TOTP totp = new TOTP();
                ncode = totp.create(key, base, digits);
            }

            // compare OTP codes
            return code.equals(ncode);
        } catch (Exception e) {
            throw new OTPException(e.getMessage());
        }
    }

    /**
     * Validate the parameters used for generating one-time passwords.
     * 
     * @param secret
     *            Shhhhh. (Base32)
     * @param base
     *            The base or counter.
     * @param digits
     *            Length of code (Commonly '6')
     * @param type
     *            TOTP or HOTP
     * @return true if parameters are valid
     * @throws BadOperationException
     *             Error when parameters invalid.
     */
    private static boolean validateParameters(String secret, String base, int digits, String type)
            throws BadOperationException {
        if (secret == null || secret.isEmpty()) {
            throw new BadOperationException("Secret cannot be null or empty.");
        }
        if (base == null || base.isEmpty()) {
            throw new BadOperationException("Base cannot be null or empty.");
        }
        if (type == null || type.isEmpty()) {
            throw new BadOperationException("Type cannot be null or empty.");
        }
        if (digits <= 0) {
            throw new BadOperationException("Digits must be a positive integer (e.g. '6').");
        }
        if (!type.equalsIgnoreCase(HOTP) && !type.equalsIgnoreCase(TOTP)) {
            throw new BadOperationException("OTP type not recognized.");
        }
        return true;
    }
}
