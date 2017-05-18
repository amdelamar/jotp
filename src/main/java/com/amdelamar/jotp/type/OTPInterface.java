package com.amdelamar.jotp.type;

/**
 * OTP (One Time Password) generator
 * 
 * @author kamranzafar, amdelamar
 */
public interface OTPInterface {

    public abstract String create(String key, String base, int digits);

}
