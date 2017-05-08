# Jotp

[![Build](https://travis-ci.org/amdelamar/jotp.svg?branch=master)](https://travis-ci.org/amdelamar/jotp)
[![Code Climate](https://codeclimate.com/github/amdelamar/jotp/badges/gpa.svg)](https://codeclimate.com/github/amdelamar/jotp)
[![License](https://img.shields.io/:license-apache-blue.svg)](https://github.com/amdelamar/jotp/blob/master/LICENSE)

OTP (One Time Password) utility in Java. To enable two-factor authentication (2FA) using [HMAC-based](https://tools.ietf.org/html/rfc4226)) or [Time-based](https://tools.ietf.org/html/rfc6238) algorithms.


## Getting Started

* Maven `coming soon`.
* Gradle `coming soon`.
* Zip with examples `coming soon`.

```
// Random secret Base32 with 20 bytes (160 bits) length
// (Use this to setup 2FA for new accounts).
String secret = OTP.randomBase32(20);
// Returns: GBMDMWBQI5KVEURWI5CT

// Generate a Time-based OTP from the secret, using Unix-time
// rounded down to the nearest 30 seconds.
String code = OTP.createTotp(secret, OTP.getTimeInHex(), 6);


// Show User QR Code (1)
// Easiest way to do this is through Goolge APIs, but I
// plan to add a 'generateImage()' function soon.
// https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl=200x200&chld=M|0&cht=qr&chl=otpauth://totp/Example:hello@example.com?secret=GBMDMWBQI5KVEURWI5CT&issuer=Example&algorithm=SHA1&digits=6&period=30
```
[![QR Image Example](https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl=200x200&chld=M|0&cht=qr&chl=otpauth://totp/Example:hello@example.com?secret=GBMDMWBQI5KVEURWI5CT&issuer=Example&algorithm=SHA1&digits=6&period=30)](https://developers.google.com/chart/infographics/docs/qr_codes)
```
// After user scans the image with their mobile app...

// Get User's input code for a login.
String userEnteredCode = "123456";

// Verify OTP
if(OTP.verifyTotp(secret, userEnteredCode, 6)) {
    // Code valid. Login successful.
}
```


## Details

This code currently supports the standard HMAC-based (HOTP [RFC 4226](https://tools.ietf.org/html/rfc4226)) and time-based (TOTP [RFC 6238](https://tools.ietf.org/html/rfc6238)) algorithms for one-time passwords.


## Credit

A project by [Austin Delamar](https://github.com/amdelamar) based off of [Kamron Zafar's work](https://github.com/kamranzafar/libotp) and other [contributors](https://github.com/amdelamar/jotp/graphs/contributors).

## License

[Apache 2.0](https://github.com/amdelamar/jotp/blob/master/LICENSE)

<sup>1</sup> QR code standard is trademarked by [Denso Wave, Inc](http://www.denso-wave.com/qrcode/index-e.html).
