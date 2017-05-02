# Jotp

OTP (One Time Password) utility in Java.

---


## Usage

This code generates OTPs and can verify them easily.

Example of Time-based OTP:

`OTP.generate("12345678", "" + System.currentTimeMillis(), 6, "totp")`

Example of Counter-based OTP:

`OTP.generate("helloworld", "2", 6, "hotp")`


## Customize

Custom OTP providers can also be written by implementing the `OTPProvider` interface.



## Details

Jotp is a simple java One-time password generator library, which can easily be used to facilitate two-factor authentication in Java applications. It currently supports the standard RFC counter based (HOTP) and time based (TOTP) algorithms.


## License

[Apache 2.0](https://github.com/amdelamar/jotp/blob/master/LICENSE)