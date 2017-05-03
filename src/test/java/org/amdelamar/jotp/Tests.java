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
            String code1 = OTP.generate(secret, "" + System.currentTimeMillis(), 6, OTP.Type.TOTP);

            // 30 sec window, so wait just 1 second
            // This will output a different base value
            Thread.sleep(1000);            

            String code2 = OTP.generate(secret, "" + System.currentTimeMillis(), 6, OTP.Type.TOTP);

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
            String code1 = OTP.generate(secret, "" + System.currentTimeMillis(), 6, OTP.Type.HOTP);

            // Indefinite window of opportunity here.
            // Next generated code SHOULD be different than the previous.
            Thread.sleep(1000);          

            String code2 = OTP.generate(secret, "" + System.currentTimeMillis(), 6, OTP.Type.HOTP);

            // compare OTP codes
            assertNotEquals(code1, code2);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
