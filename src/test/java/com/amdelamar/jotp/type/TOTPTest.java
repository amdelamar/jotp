package com.amdelamar.jotp.type;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.amdelamar.jotp.OTP;

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

        // run 5 tests
        for (int i = 0; i < 5; i++) {
            String secret = OTP.randomBase32(OTP.BYTES);
            String code1 = OTP.create(secret, OTP.timeInHex(), 6, Type.TOTP);

            // 30 sec window, so wait just a second
            // If its beyond 30sec since the first OTP,
            // then we will get a different base value.
            Thread.sleep(500);

            String code2 = OTP.create(secret, OTP.timeInHex(), 6, Type.TOTP);
            assertEquals(code1, code2);
            assertTrue(OTP.verify(secret, OTP.timeInHex(), code2, 6, Type.TOTP));
        }
    }
    
    @Test
    public void padLeft() throws InvalidKeyException, IllegalArgumentException, NoSuchAlgorithmException, IOException {
        String secret = OTP.randomBase32(OTP.BYTES);
        String code1 = OTP.create(secret, OTP.timeInHex(), 16, Type.TOTP);
        
        // code padded with 00's until it meets length desired
        // e.g. 0000001868692305
        assertEquals(16, code1.length());
        assertTrue(code1.startsWith("0"));
    }
}
