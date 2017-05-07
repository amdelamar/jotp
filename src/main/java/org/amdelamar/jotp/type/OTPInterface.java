package org.amdelamar.jotp.type;

import org.amdelamar.jotp.OTP.Type;

/**
 * OTP (One Time Password) generator
 * 
 * @author kamranzafar, amdelamar
 */
public interface OTPInterface {

    public abstract Type getType();

    public abstract String create(String key, String base, int digits);

}
