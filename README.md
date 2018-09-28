# Asynchronous http(s) client based on Boost::Beast

Usage:
```sh
$ ./main <host> <port> <target> [<HTTP version: 1.0 or 1.1(default)>]
```

Example of use:

- HTTP
```sh
$ ./main http://example.com 80 / 1.0
```
You can also pass a host without a protocol (by default, the HTTP is used).

- HTTPS
```sh
$ ./main https://www.boost.org 443 /LICENSE_1_0.txt 1.1
```


Example of SSL certificate verify failed:

```sh
$ ./main https://self-signed.badssl.com 443 /index.html
Verifying /C=US/ST=California/L=San Francisco/O=BadSSL/CN=*.badssl.com
handshake: certificate verify failed
```
