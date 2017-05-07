package org.amdelamar.jotp;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;

import org.amdelamar.jotp.exception.BadOperationException;
import org.amdelamar.jotp.type.HOTP;
import org.amdelamar.jotp.type.TOTP;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;

/**
 * OTP (One Time Password) utility in Java. To enable two-factor authentication (2FA) using HMAC-based) or Time-based algorithms.
 * 
 * @author amdelamar
 * @see https://github.com/amdelamar/jotp
 */
public class OTP {
    
    /**
     * HmacSHA1, HmacSHA256, HmacSHA512
     */
    public static final String HMACSHA1_ALGORITHM = "HmacSHA1";
    public static final String HMACSHA256_ALGORITHM = "HmacSHA256";
    public static final String HMACSHA512_ALGORITHM = "HmacSHA512";

    public static enum Type {
        HOTP, TOTP
    }

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
     * Generate a random string in Hexadecimal, with the specified length.
     * 
     * @param length
     *            default 20
     * @return secure random string
     */
    public static String randomHex(int length) {
        if (length < 1) {
            length = BYTES;
        }
        byte[] bytes = new byte[length];
        java.security.SecureRandom random = new java.security.SecureRandom();
        random.nextBytes(bytes);

        return Hex.encodeHexString(bytes);
    }

    /**
     * A quick method to get Unix Time rounded down to the nearest 30 seconds.
     * 
     * @return String Hex time
     */
    public static String getTimeInHex() {
        try {
            long time = (long) Math
                    .floor(Math.round(((double) System.currentTimeMillis()) / 1000.0) / 30L);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeLong(time);
            dos.close();
            byte[] longBytes = baos.toByteArray();
            return Hex.encodeHexString(longBytes);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Create a one-time-password with the given key, base, digits, and OTP.Type.
     * 
     * @param key
     *            The secret. Shhhhhh!
     * @param base
     *            The offset. (e.g. TOTP base is time from UTC rounded to the half-second while HOTP
     *            is a counter)
     * @param digits
     *            The length of the code (Commonly '6')
     * @param type
     *            Type.TOTP or Type.HOTP
     * @return code
     * @throws BadOperationException
     * @see https://tools.ietf.org/html/rfc4226
     * @see https://tools.ietf.org/html/rfc6238
     */
    public static String create(String key, String base, int digits, Type type)
            throws BadOperationException {

        if (type == Type.HOTP) {
            HOTP hotp = new HOTP();
            return hotp.create(key, base, digits);
        } else if (type == Type.TOTP) {
            TOTP totp = new TOTP();
            return totp.create(key, base, digits);
        } else {
            // Type not recognized
            throw new BadOperationException("OTP Type not recognized.");
        }
    }

    /**
     * Create a one-time-password with the given key, base, and digits.
     * 
     * @param key
     *            The secret. Shhhhhh!
     * @param base
     *            The offset. (HOTP is a counter incremented by each use)
     * @param digits
     *            The length of the code (Commonly '6')
     * @return code
     * @throws BadOperationException
     * @see https://tools.ietf.org/html/rfc4226
     */
    public static String createHotp(String key, String base, int digits) {
        HOTP hotp = new HOTP();
        return hotp.create(key, base, digits);
    }

    /**
     * Create a one-time-password with the given key, base, and digits.
     * 
     * @param key
     *            The secret. Shhhhhh!
     * @param base
     *            The offset. (TOTP base is time from UTC rounded to the half-second)
     * @param digits
     *            The length of the code (Commonly '6')
     * @return code
     * @throws BadOperationException
     * @see https://tools.ietf.org/html/rfc6238
     */
    public static String createTotp(String key, String base, int digits) {
        TOTP totp = new TOTP();
        return totp.create(key, base, digits);
    }

    /**
     * Returns true if the code is valid for the Hmac-based OTP of the secret.
     * 
     * @param secret
     *            Shhhhh. (Base32)
     * @param base
     *            The base or counter.
     * @param code
     *            An OTP code to check.
     * @param digits
     *            Length of code (Commonly '6')
     * @return true if valid
     * @see https://tools.ietf.org/html/rfc4226
     */
    public static boolean verifyHotp(String secret, String base, String code, int digits) {
        try {
            // convert Base32 secret to Hex
            byte[] bytes = new Base32().decode(secret);
            String key = Hex.encodeHexString(bytes);

            String ncode = createHotp(key, base, digits);

            // compare OTP codes
            return code.equals(ncode);

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Returns true if the code is valid for the Time-based OTP of the secret. The 'base' is already
     * determined to be Unix-time rounded down to the nearest 30 seconds via "getTimeInHex()". But
     * you can use the other "verityTotp()" method to provide your own base if needed.
     * 
     * @param secret
     *            Shhhhh. (Base32)
     * @param code
     *            An OTP code to check.
     * @param digits
     *            Length of code (Commonly '6')
     * @return true if valid
     * @see https://tools.ietf.org/html/rfc6238
     */
    public static boolean verifyTotp(String secret, String code, int digits) {
        try {
            // get base time in Hex
            String base = getTimeInHex();

            // convert Base32 secret to Hex
            byte[] bytes = new Base32().decode(secret);
            String key = Hex.encodeHexString(bytes);

            String ncode = createTotp(key, base, digits);

            // compare OTP codes
            return code.equals(ncode);

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Returns true if the code is valid for the Time-based OTP of the secret. The 'base' is already
     * determined to be Unix-time rounded down to the nearest 30 seconds via "getTimeInHex()". But
     * you can use the other "verityTotp()" method to provide your own base if needed.
     * 
     * @param secret
     *            Shhhhh. (Base32)
     * @param base
     *            The base or counter. In this case, its time in steps.
     * @param code
     *            An OTP code to check.
     * @param digits
     *            Length of code (Commonly '6')
     * @return true if valid
     * @see https://tools.ietf.org/html/rfc6238
     */
    public static boolean verifyTotp(String secret, String base, String code, int digits) {
        try {
            // convert Base32 secret to Hex
            byte[] bytes = new Base32().decode(secret);
            String key = Hex.encodeHexString(bytes);

            String ncode = createTotp(key, base, digits);

            // compare OTP codes
            return code.equals(ncode);

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }
}
