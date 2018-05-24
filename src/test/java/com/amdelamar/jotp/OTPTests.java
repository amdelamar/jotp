package com.amdelamar.jotp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.amdelamar.jotp.type.HOTP;
import com.amdelamar.jotp.type.TOTP;
import com.amdelamar.jotp.type.Type;

/**
 * Unit tests for Jotp
 * 
 * @author amdelamar
 * @since 1.0.0
 */
@RunWith(JUnit4.class)
public class OTPTests {

    @Test
    public void constructorTests() {
        HOTP hotp = new HOTP();
        assertNotNull(hotp);

        TOTP totp = new TOTP();
        assertNotNull(totp);
    }

    @Test
    public void labelTests() {
        HOTP hotp = new HOTP();
        assertEquals("hotp", hotp.getLabel());

        TOTP totp = new TOTP();
        assertEquals("totp", totp.getLabel());
    }

    @Test
    public void randomTests() {

        assertNotNull(OTP.randomBase32(0));
        assertNotNull(OTP.random("123", 0));

        String r1 = OTP.randomBase32(20);
        String r2 = OTP.randomBase32(20);
        assertNotEquals(r1, r2);

        assertNotNull(OTP.random("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 12));

        String r3 = OTP.random("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 12);
        String r4 = OTP.random("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 12);
        assertNotEquals(r3, r4);
    }

    @Test
    public void timeTests() throws IllegalArgumentException, IOException, InterruptedException {

        String t1 = OTP.timeInHex();
        String t2 = OTP.timeInHex();

        // wait a half second
        Thread.sleep(500);

        String t3 = OTP.timeInHex(System.currentTimeMillis());

        assertEquals(t1, t2);
        assertEquals(t1, t3);
    }

    @Test
    public void encodeTests() {

        // run 5 tests
        for (int i = 0; i < 5; i++) {
            assertNotNull(OTP.random("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 12));
        }

        // run 5 tests
        for (int i = 0; i < 5; i++) {
            assertNotNull(OTP.randomBase32(OTP.BYTES));
        }
    }

    @Test
    public void urlTests() throws IllegalArgumentException {

        String url = OTP.getURL(OTP.randomBase32(OTP.BYTES), 6, Type.HOTP, "Example1", "test1@example.com");
        assertNotNull(url);

        url = OTP.getURL(OTP.randomBase32(OTP.BYTES), 4, Type.HOTP, "Example2", "test2@example.com");
        assertNotNull(url);

        url = OTP.getURL(OTP.randomBase32(OTP.BYTES), 6, Type.TOTP, "Example3", "test3@example.com");
        assertNotNull(url);

        url = OTP.getURL(OTP.randomBase32(OTP.BYTES), 4, Type.TOTP, "Example4", "test4@example.com");
        assertNotNull(url);
    }

    @Test
    public void totpTests() throws IllegalArgumentException, IOException, InterruptedException {

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
    public void hotpTests() throws IllegalArgumentException {

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
    public void nullTests() {

        try {
            // bad secret
            OTP.create(null, OTP.timeInHex(), 6, Type.TOTP);
            fail("null secret not detected");
        } catch (Exception e) {
            // good catch
        }

        try {
            // bad base
            OTP.create("123", null, 6, Type.TOTP);
            fail("null base not detected");
        } catch (Exception e) {
            // good catch
        }

        try {
            // bad digits
            OTP.create("123", OTP.timeInHex(), 0, Type.TOTP);
            fail("zero digits not detected");
        } catch (Exception e) {
            // good catch
        }

        try {
            // bad type
            OTP.create("123", OTP.timeInHex(), 6, null);
            fail("null type not detected");
        } catch (Exception e) {
            // good catch
        }

        try {
            // null verify code
            OTP.verify("123", OTP.timeInHex(), null, 6, Type.TOTP);
            fail("null code not detected");
        } catch (Exception e) {
            // good catch
        }

        try {
            // empty verify code
            OTP.verify("123", OTP.timeInHex(), "", 6, Type.TOTP);
            fail("empty code not detected");
        } catch (Exception e) {
            // good catch
        }

        try {
            // bad verify code length
            boolean flag = OTP.verify("123", OTP.timeInHex(), "12345", 6, Type.TOTP);
            assertFalse(flag);
        } catch (Exception e) {
            fail("bad code length not detected");
        }
    }
}
