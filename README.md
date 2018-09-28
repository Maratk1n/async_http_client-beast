# Asynchronous http(s) client based on Boost::Beast

Usage:
```sh
 $ ./main --help
 HTTP client options:
  -s [ --host ] arg     Host, e.g.: localhost, http://example.com
  -p [ --port ] arg     Port number
  -t [ --target ] arg   Targer (at least '/')
  -H [ --http ] arg     HTTP version, optional parameter (by default, version 
                        is 1.1)
  -o [ --output ] arg   The output file path for recording the target. Optional
                        parameter
  -h [ --help ]         Show help

```

Example of use:

- HTTP
```sh
$ ./main -s http://example.com -p 80 -t / -H 1.0
```
You can also pass a host without a protocol (by default, the HTTP is used).

- HTTPS
```sh
$ ./main -s https://www.boost.org -p 443 -t /LICENSE_1_0.txt -H 1.1 -o /tmp/test.txt
```


Example of SSL certificate verify failed:

```sh
$ ./main https://self-signed.badssl.com 443 /index.html
Verifying /C=US/ST=California/L=San Francisco/O=BadSSL/CN=*.badssl.com
handshake: certificate verify failed
```
