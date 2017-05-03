package org.amdelamar.jotp;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;

import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class Tests {

    @Test
    public void testTOTP() {

        try {
            String secret = "HelloWorld";
            String code = OTP.generate(secret, "" + System.currentTimeMillis(), 6, OTP.Type.TOTP);

            // 30 sec window, so wait just 5 seconds
            Thread.sleep(5000);

            // get base time in Hex
            long t = (long) Math.floor(Math.round(((double) System.currentTimeMillis()) / 1000.0) / 30l);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeLong(t);
            dos.close();
            byte[] longBytes = baos.toByteArray();
            String base = Hex.encodeHexString(longBytes);

            // convert Base32 secret to Hex
            byte[] bytes = new Base32().decode(secret);
            String key = Hex.encodeHexString(bytes);

            String t0code = OTP.generate(key, base, 6, OTP.Type.TOTP);

            // compare OTP codes
            assertEquals(code, t0code);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Test
    public void testHOTP() {
        // TODO
        assertEquals(true, true);
    }

}
