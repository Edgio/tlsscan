# tlsscan
> _TLS/SSL protocol/cipher scanner (based on work from [sslscan](https://github.com/rbsec/sslscan))_


## Table of Contents

- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [License](#license)


## Background
`tlsscan` is a basic command line TLS scanner using [OpenSSL](https://www.openssl.org/) to display protocols and ciphers supported by a remote TLS server application.  The tool is based on previous work: [sslscan](https://github.com/rbsec/sslscan), but updated somewhat to support newer protocols and ciphers via later releases of upstream [OpenSSL](https://www.openssl.org/) project.

Other more authoritative and accurate references for scanning including sources like [Qualys, SSL Labs](https://www.ssllabs.com/ssltest/) should also be referenced, and as such `tlsscan` is provided on an _"as is"_ basis.


## Install

### Building tlsscan from source

Run the `build.sh` script to pull down OpenSSL and build
```sh
./build.sh
```

### Installation
Install from the build directory with
```sh
cd build && make install
```

### Running

```sh
~>tlsscan google.com
Connected to 172.217.14.110:443

Testing SSL server google.com on port 443 using SNI name google.com

  SSL/TLS Protocols:
    TLSv1.3 is enabled
    TLSv1.2 is enabled
    TLSv1.1 is enabled
    TLSv1   is enabled
    SSLv3   is not enabled
    SSLv2   is not enabled

  TLS Fallback SCSV:
    Server                supports TLS Fallback SCSV

  TLS renegotiation:
    Session renegotiation secure supported

  Supported Server Cipher(s):
    Preferred TLSv1.3  128 bits  TLS_AES_128_GCM_SHA256        Curve 25519 DHE 253
    Accepted  TLSv1.3  256 bits  TLS_AES_256_GCM_SHA384        Curve 25519 DHE 253
    Accepted  TLSv1.3  256 bits  TLS_CHACHA20_POLY1305_SHA256  Curve 25519 DHE 253
    Preferred TLSv1.2  256 bits  ECDHE-ECDSA-CHACHA20-POLY1305 Curve 25519 DHE 253
    Accepted  TLSv1.2  128 bits  ECDHE-ECDSA-AES128-GCM-SHA256 Curve 25519 DHE 253
    Accepted  TLSv1.2  256 bits  ECDHE-ECDSA-AES256-GCM-SHA384 Curve 25519 DHE 253
    Accepted  TLSv1.2  256 bits  ECDHE-RSA-CHACHA20-POLY1305   Curve 25519 DHE 253
    Accepted  TLSv1.2  128 bits  ECDHE-RSA-AES128-GCM-SHA256   Curve 25519 DHE 253
...             

  Server Key Exchange Group(s):
    TLSv1.3  128 bits  secp256r1 (NIST P-256)
    TLSv1.3  128 bits  x25519
    TLSv1.2  128 bits  secp256r1 (NIST P-256)
    TLSv1.2  128 bits  x25519

  Server Signature Algorithm(s):
    TLSv1.3 rsa_pkcs1_nohash
    TLSv1.3 dsa_nohash
...


  SSL Certificate:
    Serial Number:        cb:fd:0b:25:61:65:6e:a2:02:00:00:00:00:5c:67:5c
    Signature Algorithm:  sha256WithRSAEncryption
    Subject:              *.google.com
    Altnames:             DNS:*.google.com, DNS:*.android.com, DNS:*.appengine.google.com, DNS:*.cloud.google.com, DNS:*.crowdsource.google.com, DNS:*.g.co, ...
    Issuer:               GTS CA 1O1
    Not valid before:     Mar  3 09:45:25 2020 GMT
    Not valid after:      May 26 09:45:25 2020 GMT
```


## Usage
`tlsscan --help`

```sh
Options:
  -h, --help                display this help and exit.
  -V, --version             display the version number and exit.
  
Run Options:
  -4, --ipv4                resolve name to IPv4 address.
  -6, --ipv6                resolve name to IPv6 address.
  -t, --tls_options         TLS options string.
  -s, --ocsp                check OCSP response.
  -m, --compression         check for compression.
  -e, --heartbleed          check for heartbleed.
  
Display Options:
  -C, --show_cert           show server cert info.
  -A, --show_cas            show trusted CA's for client auth.
  -L, --show_client_ciphers show supported client ciphers.

```

## Contribute

- We welcome issues, questions and pull requests.


## License

This project is licensed under the terms of the Apache 2.0 open source license. Please refer to the `LICENSE-2.0.txt` file for the full terms.
