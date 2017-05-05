package org.amdelamar.jotp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class Tests {

    @Test
    public void testTOTP() {
        try {
            String secret = "HelloWorld";
            String code1 = OTP.createTOTP(secret, "" + System.currentTimeMillis(), 6);

            // 30 sec window, so wait just 1 second
            // This will output a different base value
            Thread.sleep(1000);

            String code2 = OTP.createTOTP(secret, "" + System.currentTimeMillis(), 6);

            // compare OTP codes
            assertEquals(code1, code2);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testHOTP() {
        try {
            String secret = "HelloWorld";
            String code1 = OTP.createHOTP(secret, "1", 6);

            // Indefinite window of opportunity here.
            // Next generated code SHOULD be different than the previous.
            Thread.sleep(1000);

            String code2 = OTP.createHOTP(secret, "2", 6);

            // compare OTP codes
            assertNotEquals(code1, code2);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
