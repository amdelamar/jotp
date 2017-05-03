# Jotp

OTP (One Time Password) utility in Java.


## Getting Started

* Maven `coming soon`.
* Gradle `coming soon`.
* Zip with examples `coming soon`.

This code generates OTPs and can verify them easily.

Example of Time-based OTP:

`OTP.generateTOTP("HelloWorld!", "" + System.currentTimeMillis(), 6)`

Example of Counter-based OTP:

`OTP.generateHOTP("HelloWorld!", "2", 6,)`


## Customize

Custom OTP providers can also be written by implementing the `OTPProvider` interface.


## Details

This code generates one-time-passwords, which can easily be used to facilitate two-factor authentication in Java applications. It currently supports the standard HMAC-based (HOTP [RFC 4226](https://tools.ietf.org/html/rfc4226)) and time-based (TOTP [RFC 6238](https://tools.ietf.org/html/rfc6238)) algorithms.


## Credit

A project by [Austin Delamar](https://github.com/amdelamar) based off of [Kamron Zafar's work](https://github.com/kamranzafar/libotp) and contributed to by [Others](https://github.com/amdelamar/jotp/graphs/contributors).

## License

[Apache 2.0](https://github.com/amdelamar/jotp/blob/master/LICENSE)
