package com.amdelamar.jotp;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import com.amdelamar.jotp.type.HOTP;
import com.amdelamar.jotp.type.TOTP;
import com.amdelamar.jotp.type.Type;
import org.apache.commons.codec.binary.Hex;

/**
 * OTP (One Time Password) utility in Java. To enable two-factor authentication (2FA) using
 * HMAC-based) or Time-based algorithms.
 *
 * @author amdelamar
 * @see <a href="https://github.com/amdelamar/jotp">https://github.com/amdelamar/jotp</a>
 * @since 1.0.0
 */
public final class OTP {

    public static final int BYTES = 20; // 160 bit

    private OTP() {
        // prevent instantiation
    }

    /**
     * Generate a random string using the characters provided, with the specified length.
     *
     * @param characters
     *            A set of possible characters to be chosen.
     * @param length
     *            default 20
     * @return secure random string
     */
    @Deprecated
    public static String random(String characters, int length) {
        final int len = length < 1 ? BYTES : length;
        final SecureRandom random = new SecureRandom();
        char[] text = new char[len];
        for (int i = 0; i < len; i++) {
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
        final int len = length < 1 ? BYTES : length;
        byte[] bytes = new byte[len];
        final SecureRandom random = new SecureRandom();
        random.nextBytes(bytes);

        return new org.apache.commons.codec.binary.Base32().encodeToString(bytes);
    }

    /**
     * A quick method to get Unix Time rounded down to the nearest 30 seconds.
     *
     * @return String Hex time
     * @throws IOException when generating Unix time
     */
    @Deprecated
    public static String timeInHex() throws IOException {
        return timeInHex(System.currentTimeMillis());
    }

    /**
     * A quick method to get a Time rounded down to the nearest 30 seconds.
     * @param timeInMillis long (like <code>System.currentTimeMillis()</code>)
     * @return String Hex time
     * @throws IOException when generating Unix time
     */
    public static String timeInHex(long timeInMillis) throws IOException {
        return timeInHex(timeInMillis, 30);
    }

    /**
     * A method to get a Unix Time converted to Hexadecimal using a token period.
     * @param timeInMillis long (like <code>System.currentTimeMillis()</code>)
     * @param periodInSec int seconds period for the time to be rounded down to
     * @return String Hex time
     * @throws IOException
     */
    public static String timeInHex(long timeInMillis, int periodInSec) throws IOException {
        double period = 1d;
        if (periodInSec > 1) {
            // ensure period is 1 or greater value
            period = periodInSec;
        }
        final long time = (long) Math.floor(Math.round(((double) timeInMillis) / 1000d) / period);
        final byte[] longBytes = ByteBuffer.allocate(Long.SIZE / Byte.SIZE)
                .putLong(time)
                .array();
        return new String(Hex.encodeHex(longBytes));
    }

    /**
     * Create a one-time-password with the given key, base, digits, and OTP.Type.
     *
     * @param secret
     *            The secret.
     * @param base
     *            The offset. (e.g. TOTP base is time from UTC rounded to the half-second while HOTP
     *            is a counter)
     * @param digits
     *            The length of the code (Commonly '6')
     * @param type
     *            Type.TOTP or Type.HOTP
     * @return code
     * @throws IllegalArgumentException when parameters are invalid
     * @throws NoSuchAlgorithmException when HMAC is not available on this jvm
     * @throws InvalidKeyException when secret is invalid
     * @see <a href="https://tools.ietf.org/html/rfc4226">https://tools.ietf.org/html/rfc4226</a>
     * @see <a href="https://tools.ietf.org/html/rfc6238">https://tools.ietf.org/html/rfc6238</a>
     */
    public static String create(String secret, String base, int digits, Type type)
            throws IllegalArgumentException, InvalidKeyException, NoSuchAlgorithmException {

        // validate
        validateParameters(secret, base, digits, type);

        // Base32 Secret should be UPPERCASED
        final String uppercaseSecret = secret.toUpperCase();

        // convert Base32 secret to Hex
        final byte[] bytes = new org.apache.commons.codec.binary.Base32().decode(uppercaseSecret);
        final String key = new String(Hex.encodeHex(bytes));

        if (type == Type.HOTP) {
            final HOTP hotp = new HOTP();
            return hotp.create(key, base, digits);
        } else {
            final TOTP totp = new TOTP();
            return totp.create(key, base, digits);
        }
    }

    /**
     * Returns true if the code is valid for the Hmac-based or Time-based OTP of the secret.
     *
     * For Hmac-based the 'base' is a counter, like 1,2,3. For Time-based the 'base' is Unix-time
     * rounded down to the nearest 30 seconds.
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
     *            Type.TOTP or Type.HOTP
     * @return true if valid
     * @throws IllegalArgumentException when parameters are invalid
     * @throws NoSuchAlgorithmException when HMAC is not available on this jvm
     * @throws InvalidKeyException when secret is invalid
     * @see <a href="https://tools.ietf.org/html/rfc4226">https://tools.ietf.org/html/rfc4226</a>
     * @see <a href="https://tools.ietf.org/html/rfc6238">https://tools.ietf.org/html/rfc6238</a>
     */
    public static boolean verify(String secret, String base, String code, int digits, Type type)
            throws IllegalArgumentException, InvalidKeyException, NoSuchAlgorithmException {

        // validate
        validateParameters(secret, base, digits, type);

        // Base32 Secret should be UPPERCASED
        final String uppercaseSecret = secret.toUpperCase();

        if (code == null || code.isEmpty()) {
            throw new IllegalArgumentException("Code cannot be null or empty.");
        }
        if (code.length() != digits) {
            // code length must match digits
            return false;
        }

        // convert Base32 secret to Hex
        final byte[] bytes = new org.apache.commons.codec.binary.Base32().decode(uppercaseSecret);
        final String key = new String(Hex.encodeHex(bytes));

        // generate code to compare
        String ncode = null;
        if (type == Type.HOTP) {
            final HOTP hotp = new HOTP();
            ncode = hotp.create(key, base, digits);
        } else {
            final TOTP totp = new TOTP();
            ncode = totp.create(key, base, digits);
        }

        // compare OTP codes
        return code.equals(ncode);
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
     *            Type.TOTP or Type.HOTP
     * @return true if parameters are valid
     * @throws IllegalArgumentException when parameters are invalid
     */
    protected static boolean validateParameters(String secret, String base, int digits, Type type)
            throws IllegalArgumentException {
        if (secret == null || secret.isEmpty()) {
            throw new IllegalArgumentException("Secret cannot be null or empty.");
        }
        if (base == null || base.isEmpty()) {
            throw new IllegalArgumentException("Base cannot be null or empty.");
        }
        if (type == null) {
            throw new IllegalArgumentException("Type cannot be null or empty.");
        }
        if (digits <= 0) {
            throw new IllegalArgumentException("Digits must be a positive integer (e.g. '6').");
        }
        return true;
    }

    /**
     * Gets the "otpauth://" URL for adding to 2FA compatible devices/apps.
     *
     * @param secret
     *            Shhhhh. (Base32)
     * @param digits
     *            Length of code (Commonly '6')
     * @param type
     *            Type.TOTP or Type.HOTP
     * @param issuer
     *            Company or Domain name
     * @param email
     *            Username or Email address
     * @return otpauth://...
     * @throws IllegalArgumentException when parameters are invalid
     */
    public static String getURL(String secret, int digits, Type type, String issuer, String email)
            throws IllegalArgumentException {

        validateParameters(secret, secret, digits, type);

        StringBuilder sb = new StringBuilder();
        sb.append("otpauth://");

        if (type == Type.HOTP) {
            sb.append("hotp/");
        } else {
            sb.append("totp/");
        }

        sb.append(issuer + ":");
        sb.append(email + "?");
        sb.append("secret=" + secret);
        sb.append("&issuer=" + issuer);
        sb.append("&algorithm=SHA1");
        sb.append("&digits=" + digits);

        if (type == Type.TOTP) {
            sb.append("&period=30");
        }

        return sb.toString();
    }
}
