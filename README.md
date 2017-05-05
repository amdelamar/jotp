# Jotp

[![Build](https://travis-ci.org/amdelamar/jotp.svg?branch=master)](https://travis-ci.org/amdelamar/jotp)
[![Code Climate](https://codeclimate.com/github/amdelamar/jotp/badges/gpa.svg)](https://codeclimate.com/github/amdelamar/jotp)
[![License](https://img.shields.io/:license-apache-blue.svg)](https://github.com/amdelamar/jotp/blob/master/LICENSE)

OTP (One Time Password) utility in Java. To enable two-factor authentication (2FA) using [HMAC-based](https://tools.ietf.org/html/rfc4226)) or [Time-based](https://tools.ietf.org/html/rfc6238) algorithms.


## Getting Started

* Maven `coming soon`.
* Gradle `coming soon`.
* Zip with examples `coming soon`.

Example of Time-based OTP:

`OTP.generateTOTP("HelloWorld!", "" + System.currentTimeMillis(), 6)`

Example of Counter-based OTP:

`OTP.generateHOTP("HelloWorld!", "2", 6,)`


## Details

This code currently supports the standard HMAC-based (HOTP [RFC 4226](https://tools.ietf.org/html/rfc4226)) and time-based (TOTP [RFC 6238](https://tools.ietf.org/html/rfc6238)) algorithms for one-time passwords.


## Credit

A project by [Austin Delamar](https://github.com/amdelamar) based off of [Kamron Zafar's work](https://github.com/kamranzafar/libotp) and other [contributors](https://github.com/amdelamar/jotp/graphs/contributors).

## License

[Apache 2.0](https://github.com/amdelamar/jotp/blob/master/LICENSE)
