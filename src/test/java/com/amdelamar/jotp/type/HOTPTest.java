package com.amdelamar.jotp.type;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.amdelamar.jotp.OTP;

/**
 * Unit tests for HOTP
 */
@RunWith(JUnit4.class)
public class HOTPTest {

    @Test
    public void constructorTests() {
        HOTP hotp = new HOTP();
        assertNotNull(hotp);
    }

    @Test
    public void labelTests() {
        HOTP hotp = new HOTP();
        assertEquals("hotp", hotp.getLabel());
    }

    @Test
    public void hotpTests() throws IllegalArgumentException, InvalidKeyException, NoSuchAlgorithmException {

        // run 5 tests
        for (int i = 0; i < 5; i++) {
            String secret = OTP.randomBase32(OTP.BYTES);
            String code1 = OTP.create(secret, "1", 6, Type.HOTP);

            // Using same counter should get the same code
            String code2 = OTP.create(secret, "1", 6, Type.HOTP);
            assertEquals(code1, code2);
            assertTrue(OTP.verify(secret, "1", code2, 6, Type.HOTP));

            // Indefinite window of opportunity here.
            // Next generated code SHOULD be different than the previous.

            String code3 = OTP.create(secret, "2", 6, Type.HOTP);
            assertNotEquals(code1, code3);
        }
    }
    
    @Test
    public void padLeft() throws InvalidKeyException, IllegalArgumentException, NoSuchAlgorithmException {
        String secret = OTP.randomBase32(OTP.BYTES);
        String code1 = OTP.create(secret, "1", 16, Type.HOTP);
        
        // code padded with 00's until it meets length desired
        // e.g. 0000001868692305
        assertEquals(16, code1.length());
        assertTrue(code1.startsWith("0"));
    }
    
    @Test
    public void checksum() {
        HOTP hotp = new HOTP();
        
        //hotp.checksum()
    }
}
