package com.amdelamar.jotp.type;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.amdelamar.jotp.OTP;

import static org.junit.Assert.*;

/**
 * Unit tests for TOTP
 */
@RunWith(JUnit4.class)
public class TOTPTest {

    @Test
    public void constructorTests() {
        TOTP totp = new TOTP();
        assertNotNull(totp);
    }

    @Test
    public void labelTests() {
        TOTP totp = new TOTP();
        assertEquals("totp", totp.getLabel());
    }

    @Test
    public void totpTests() throws IllegalArgumentException, IOException, InterruptedException, InvalidKeyException,
            NoSuchAlgorithmException {
        // Normally we'd use System.currentTimeMillis(), but
        // because we can't control exactly when unit tests run
        // we might fail this test because the 30s window passes
        // too early. So instead, we'll pick a specific point in
        // time to make this test repeatable.
        long time = 1573788090000L;
        System.out.println("time = " + time);
        String secret = OTP.randomBase32(OTP.BYTES);
        String code1 = OTP.create(secret, OTP.timeInHex(time), 6, Type.TOTP);

        // 30 sec window, so wait just a second
        long oneSecondLater = time + 1000;

        String code2 = OTP.create(secret, OTP.timeInHex(oneSecondLater), 6, Type.TOTP);
        assertEquals(code1, code2);
        assertTrue(OTP.verify(secret, OTP.timeInHex(oneSecondLater), code2, 6, Type.TOTP));

        // If its beyond 30sec since the first OTP,
        // then we will get a different base value.
        long thirtyOneSecondsLater = oneSecondLater + 30000;
        String code3 = OTP.create(secret, OTP.timeInHex(thirtyOneSecondsLater), 6, Type.TOTP);
        assertNotEquals(code1, code3);
        assertTrue(OTP.verify(secret, OTP.timeInHex(thirtyOneSecondsLater), code3, 6, Type.TOTP));
    }
    
    @Test
    public void padLeft() throws InvalidKeyException, IllegalArgumentException, NoSuchAlgorithmException, IOException {
        long time = 1470610800000L; // Or System.currentTimeMillis()
        String secret = OTP.randomBase32(OTP.BYTES);
        String code1 = OTP.create(secret, OTP.timeInHex(time), 16, Type.TOTP);
        
        // code padded with 00's until it meets length desired
        // e.g. 0000001868692305
        assertEquals(16, code1.length());
        assertTrue(code1.startsWith("0"));
    }
}
