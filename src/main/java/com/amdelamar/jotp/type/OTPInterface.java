package com.amdelamar.jotp.type;

/**
 * OTP (One Time Password) generator interface
 * 
 * @author kamranzafar, amdelamar
 * @since 1.0.0
 */
public interface OTPInterface {
    
    public abstract String getLabel();

    public abstract String create(String key, String base, int digits);

}
