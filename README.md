# shc
Smart Health Card decoder and verifier proof of concept.  Built to work with California Vaccine Record.

Requirements:
 - OpenSSL (tested with v1.1.1)
 - zlib

Tested on Mac and Linux, and should work on embedded and mobile platforms with minimal effort.

Implements decoding and verifying the contents of a Smart Health Card as defined here:
https://spec.smarthealth.cards/

It has the public key hardcoded for the California Digital Vaccien Records, but can be easily adapted to support others (or multiple).  This is designed as a proof of concept for integrating it into a larger application.

Input is a record as it would be scanned from a QR code, starting with "shc://123456789...".  It's hardcoded as a global variable rather than creating any input mechanism, as it's not intended to be a utility for actual use.

No valid record is included given the PII it contains.  Anyone wishing to try this would need to supply their own, potentially modifying the jwks record containing the public key for their respective authority.  Ideally the key should be retrieved automatically in any real implementation.

Compilation instructions:
gcc -o shc shc.c -lz -lssl -lcrypto
