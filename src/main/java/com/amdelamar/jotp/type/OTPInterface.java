package com.amdelamar.jotp.type;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * OTP (One Time Password) generator interface
 * 
 * @author kamranzafar, amdelamar
 * @since 1.0.0
 */
public interface OTPInterface {

    public abstract String getLabel();

    public abstract String create(String key, String base, int digits) throws InvalidKeyException, NoSuchAlgorithmException;

}
