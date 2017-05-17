package org.amdelamar.jotp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.io.IOException;

import org.amdelamar.jotp.exception.BadOperationException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class Tests {

    @Test
    public void encodeTests() {

        // run 5 tests
        for (int i = 0; i < 5; i++) {
            System.out.println(OTP.random("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", 12));
        }

        // run 5 tests
        for (int i = 0; i < 5; i++) {
            System.out.println(OTP.randomBase32(OTP.BYTES));
        }
    }

    @Test
    public void totpTests() throws BadOperationException, IOException, InterruptedException {

        // run 5 tests
        for (int i = 0; i < 5; i++) {
            String secret = OTP.randomBase32(OTP.BYTES);
            String code1 = OTP.create(secret, OTP.timeInHex(), 6, "totp");

            // 30 sec window, so wait just a second
            // If its beyond 30sec since the first OTP,
            // then we will get a different base value.
            Thread.sleep(500);

            String code2 = OTP.create(secret, OTP.timeInHex(), 6, "totp");
            assertEquals(code1, code2);
        }
    }

    @Test
    public void hotpTests() throws BadOperationException {

        // run 5 tests
        for (int i = 0; i < 5; i++) {
            String secret = OTP.randomBase32(OTP.BYTES);
            String code1 = OTP.create(secret, "1", 6, "hotp");

            // Indefinite window of opportunity here.
            // Next generated code SHOULD be different than the previous.

            String code2 = OTP.create(secret, "1", 6, "hotp");
            assertEquals(code1, code2);

            String code3 = OTP.create(secret, "2", 6, "hotp");
            assertNotEquals(code1, code3);
        }
    }

}
