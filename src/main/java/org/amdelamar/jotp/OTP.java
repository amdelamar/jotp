package org.amdelamar.jotp;

import org.amdelamar.jotp.exception.BadOperationException;
import org.amdelamar.jotp.type.HOTP;
import org.amdelamar.jotp.type.TOTP;

public class OTP {
    
    public enum Type {
        HOTP, TOTP
    }

    public static String generate(String key, String base, int digits, Type type) throws BadOperationException {

        if(type == Type.HOTP) {
            HOTP hotp = new HOTP();
            return hotp.generate(key, base, digits);
        }
        else if(type == Type.TOTP) {
            TOTP totp = new TOTP();
            return totp.generate(key, base, digits);
        }
        else {
            // Type not recognized
            throw new BadOperationException("OTP Type not recognized.");
        }
    }
    
    public static String generateHOTP(String key, String base, int digits) {
        HOTP hotp = new HOTP();
        return hotp.generate(key, base, digits);
    }
    
    public static String generateTOTP(String key, String base, int digits) {
        TOTP totp = new TOTP();
        return totp.generate(key, base, digits);
    }
}
