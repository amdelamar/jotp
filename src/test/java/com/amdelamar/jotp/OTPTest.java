package com.amdelamar.jotp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.io.IOException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.amdelamar.jotp.type.Type;

/**
 * Unit tests for Jotp
 */
@RunWith(JUnit4.class)
public class OTPTest {

    @Test
    public void randomTests() {
        assertNotNull(OTP.randomBase32(0));

        String r1 = OTP.randomBase32(20);
        String r2 = OTP.randomBase32(20);
        assertNotEquals(r1, r2);
    }

    @Test
    public void timeTests() throws IllegalArgumentException, IOException, InterruptedException {
        String t1 = OTP.timeInHex(System.currentTimeMillis());
        String t2 = OTP.timeInHex(System.currentTimeMillis());

        // wait a half second
        Thread.sleep(500);

        String t3 = OTP.timeInHex(System.currentTimeMillis());

        assertEquals(t1, t2);
        assertEquals(t1, t3);
    }

    @Test
    public void encodeTests() {
        assertEquals(32, OTP.randomBase32(OTP.BYTES).length());
        assertEquals(16, OTP.randomBase32(10).length());
    }

    @Test
    public void urlTests() throws IllegalArgumentException {
        String secret = OTP.randomBase32(10);

        String url1 = OTP.getURL(secret, 6, Type.HOTP, "Example1", "test1@example.com");
        String expectedUrl1 = "otpauth://hotp/Example1:test1@example.com" +
                "?secret=" + secret + "&issuer=Example1&algorithm=SHA1&digits=6";
        assertEquals(expectedUrl1, url1);

        String url2 = OTP.getURL(secret, 4, Type.TOTP, "BobsBurgers", "bob@burgers.com");
        String expectedUrl2 = "otpauth://totp/BobsBurgers:bob@burgers.com" +
                "?secret=" + secret + "&issuer=BobsBurgers&algorithm=SHA1&digits=4&period=30";
        assertEquals(expectedUrl2, url2);
    }

    @Test
    public void badSecretTests() {
        try {
            // bad secret
            OTP.create(null, OTP.timeInHex(System.currentTimeMillis()), 6, Type.TOTP);
            fail("null secret not detected");
        } catch (Exception e) {
            // good catch
        }

        try {
            // empty secret
            OTP.create("", OTP.timeInHex(System.currentTimeMillis()), 6, Type.TOTP);
            fail("empty secret not detected");
        } catch (Exception e) {
            // good catch
        }

        try {
            // short secret
            OTP.create("123", OTP.timeInHex(System.currentTimeMillis())
                    .substring(3), 6, Type.TOTP);
            // should be ok
        } catch (Exception e) {
            // bad exception
            fail("short secret caused a problem");
        }
    }

    @Test
    public void uppercaseSecretTests() {
        try {
            String time = OTP.timeInHex(System.currentTimeMillis());
            String t1 = OTP.create("MFRGGZDFMZTWQ2LK", time, 6, Type.TOTP);
            String t2 = OTP.create("mfrggzdfmztwq2lk", time, 6, Type.TOTP);
            assertEquals(t1, t2);
        } catch (Exception e) {
            // bad exception
            fail("uppercase secret caused a problem");
        }

    }

    @Test
    public void badBaseTests() {
        try {
            // bad base
            OTP.create("123", null, 6, Type.TOTP);
            fail("null base not detected");
        } catch (Exception e) {
            // good catch
        }

        try {
            // empty base
            OTP.create("123", "", 6, Type.TOTP);
            fail("null base not detected");
        } catch (Exception e) {
            // good catch
        }
    }

    @Test
    public void badDigitTests() {
        try {
            // bad digits
            OTP.create("123", OTP.timeInHex(System.currentTimeMillis()), 0, Type.TOTP);
            fail("zero digits not detected");
        } catch (Exception e) {
            // good catch
        }

        try {
            // bad type
            OTP.create("123", OTP.timeInHex(System.currentTimeMillis()), 6, null);
            fail("null type not detected");
        } catch (Exception e) {
            // good catch
        }
    }

    @Test
    public void badCodeTests() {
        try {
            // null verify code
            OTP.verify("123", OTP.timeInHex(System.currentTimeMillis()), null, 6, Type.TOTP);
            fail("null code not detected");
        } catch (Exception e) {
            // good catch
        }

        try {
            // empty verify code
            OTP.verify("123", OTP.timeInHex(System.currentTimeMillis()), "", 6, Type.TOTP);
            fail("empty code not detected");
        } catch (Exception e) {
            // good catch
        }

        try {
            // bad verify code length
            boolean flag = OTP.verify("123", OTP.timeInHex(System.currentTimeMillis()), "12345", 6, Type.TOTP);
            assertFalse(flag);
        } catch (Exception e) {
            fail("bad code length not detected");
        }
    }
}
