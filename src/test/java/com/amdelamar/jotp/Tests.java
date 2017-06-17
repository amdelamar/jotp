package com.amdelamar.jotp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.amdelamar.jotp.OTP;
import com.amdelamar.jotp.exception.BadOperationException;
import com.amdelamar.jotp.exception.OTPException;
import com.amdelamar.jotp.type.Type;

/**
 * Unit tests for Jotp
 * 
 * @author amdelamar
 * @since 1.0.0
 */
@RunWith(JUnit4.class)
public class Tests {

    @Test
    public void randomTests() {

        assertNotNull(OTP.randomBase32(20));

        String r1 = OTP.randomBase32(20);
        String r2 = OTP.randomBase32(20);
        assertNotEquals(r1, r2);

        assertNotNull(OTP.random("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 12));

        String r3 = OTP.random("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 12);
        String r4 = OTP.random("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 12);
        assertNotEquals(r3, r4);
    }

    @Test
    public void timeTests() throws BadOperationException, IOException, InterruptedException {

        String t1 = OTP.timeInHex();
        String t2 = OTP.timeInHex();

        // wait a half second
        Thread.sleep(500);

        String t3 = OTP.timeInHex();

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
    public void urlTests() throws OTPException, BadOperationException {

        String url = OTP.getURL(OTP.randomBase32(OTP.BYTES), 6, Type.HOTP, "Example1",
                "test1@example.com");
        assertNotNull(url);

        url = OTP.getURL(OTP.randomBase32(OTP.BYTES), 4, Type.HOTP, "Example2",
                "test2@example.com");
        assertNotNull(url);

        url = OTP.getURL(OTP.randomBase32(OTP.BYTES), 6, Type.TOTP, "Example3",
                "test3@example.com");
        assertNotNull(url);

        url = OTP.getURL(OTP.randomBase32(OTP.BYTES), 4, Type.TOTP, "Example4",
                "test4@example.com");
        assertNotNull(url);
    }

    @Test
    public void totpTests() throws BadOperationException, IOException, InterruptedException {

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
        }
    }

    @Test
    public void hotpTests() throws BadOperationException {

        // run 5 tests
        for (int i = 0; i < 5; i++) {
            String secret = OTP.randomBase32(OTP.BYTES);
            String code1 = OTP.create(secret, "1", 6, Type.HOTP);

            // Indefinite window of opportunity here.
            // Next generated code SHOULD be different than the previous.

            String code2 = OTP.create(secret, "1", 6, Type.HOTP);
            assertEquals(code1, code2);

            String code3 = OTP.create(secret, "2", 6, Type.HOTP);
            assertNotEquals(code1, code3);
        }
    }

}
