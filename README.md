# Jotp

[![Build](https://img.shields.io/travis/amdelamar/jotp.svg)](https://travis-ci.org/amdelamar/jotp)
[![Code Climate](https://img.shields.io/codeclimate/github/amdelamar/jotp.svg)](https://codeclimate.com/github/amdelamar/jotp)
[![Codecov](https://img.shields.io/codecov/c/github/amdelamar/jotp.svg)](https://codecov.io/gh/amdelamar/jotp)
[![License](https://img.shields.io/:license-apache-blue.svg)](https://github.com/amdelamar/jotp/blob/master/LICENSE)
[![Release](https://img.shields.io/github/tag/amdelamar/jotp.svg?label=JitPack)](https://jitpack.io/#amdelamar/jotp)

OTP (One Time Password) utility in Java. To enable two-factor authentication (2FA) using [HMAC-based](https://tools.ietf.org/html/rfc4226)) or [Time-based](https://tools.ietf.org/html/rfc6238) algorithms.


## Getting Started

* Maven:

```xml
<repositories>
    <repository>
        <id>jitpack.io</id>
        <url>https://jitpack.io</url>
    </repository>
</repositories>
...
<dependency>
    <groupId>com.github.amdelamar</groupId>
    <artifactId>jotp</artifactId>
    <version>v1.0.0</version>
</dependency>
```

* Gradle:

```gradle
repositories {
    ...
    maven { url 'https://jitpack.io' }
}
...
dependencies {
    compile 'com.github.amdelamar:jotp:v1.0.0'
}
```

* or Download the [latest release](https://github.com/amdelamar/jotp/releases).


## Usage

```java
// Random secret Base32 with 20 bytes (160 bits) length
// (Use this to setup 2FA for new accounts).
String secret = OTP.randomBase32(20);
// Returns: IM4ZL3G5Q66KW4U7PMOQVXQQH3NGOCHQ

// Generate a Time-based OTP from the secret, using Unix-time
// rounded down to the nearest 30 seconds.
String code = OTP.create(secret, OTP.timeInHex(), 6, "totp");
```

Show the user the QR Code <sup>1</sup>

Easiest way to do this is through Goolge APIs, but I plan to add a 'generateImage()' function soon.

[![QR Image Example](https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl=200x200&chld=M|0&cht=qr&chl=otpauth://totp/Example:hello@example.com?secret=IM4ZL3G5Q66KW4U7PMOQVXQQH3NGOCHQ&issuer=Example&algorithm=SHA1&digits=6&period=30)](https://developers.google.com/chart/infographics/docs/qr_codes)
https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl=200x200&chld=M|0&cht=qr&chl=otpauth://totp/Example:hello@example.com?secret=IM4ZL3G5Q66KW4U7PMOQVXQQH3NGOCHQ&issuer=Example&algorithm=SHA1&digits=6&period=30

After user scans the image with their mobile app we can compare codes.

```java
// Get User's input code for a login...
String userEnteredCode = "123456";

// Verify OTP
if(OTP.verify(secret, userEnteredCode, 6, "totp")) {
    // Code valid. Login successful.
}
```


## Details

This code currently supports the standard HMAC-based (HOTP [RFC 4226](https://tools.ietf.org/html/rfc4226)) and time-based (TOTP [RFC 6238](https://tools.ietf.org/html/rfc6238)) algorithms for one-time passwords.

It was started as an easy way to enable 2-Factor Authentication for Java based web applications, but it can be applied to other Java applications as well.


## Contribute

A project by [Austin Delamar](https://github.com/amdelamar) based off of [Kamron Zafar's work](https://github.com/kamranzafar/libotp) and other [contributors](https://github.com/amdelamar/jotp/graphs/contributors).

If you'd like to contribute, feel free to fork and make changes, then open a pull request to master branch.


## License

[Apache 2.0](https://github.com/amdelamar/jotp/blob/master/LICENSE)

<sup>1</sup> QR code standard is trademarked by [Denso Wave, Inc](http://www.denso-wave.com/qrcode/index-e.html).
