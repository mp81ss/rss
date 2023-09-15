# ARCHIVED - Moved to gitlab


# Russian-secured-site

## Introduction
It is a *javascript* cryptography library offering a symmetric cipher and a hashing algorithm\
The encryption algorithm is [**GOST 28147-89**](https://en.wikipedia.org/wiki/GOST_(block_cipher))\
The hash algorithm is [**GOST R 34.11-94**](https://en.wikipedia.org/wiki/GOST_(hash_function)) in two variants: *standard* and *crypto*, see details below

## Details
The cipher (called *magma*) is implemented with updated sbox from **RFC 8891** in **CBC** mode

The hash function is available in two variants:
 - Standard variant (with sbox from **RFC 4351**), commonly called *GOST*
 - The *CryptoPro* variant, implemented with sbox suggested by [CryptoPro company](https://www.cryptopro.ru) in **RFC 4357**, commonly called *gost-crypto*

## Usage
### Cipher
The cipher offers two functions:
 - *encrypt*
 - *decrypt*

The *encrypt* function takes a string (plaintext) and the key, (can be an array of **8** integers or a hexadecimal string of length **64**)\
The *decrypt* function takes the ciphertext (a string returned by *encrypt*) and the key\
*Note*: There is **no way** to know if decryption was correct, you have to verify it
``` html
<script type='text/javascript' src='gost.js'></script>
```
``` js
var pt = 'gost';
var key = [0, 1, 2, 3, 4, 5, 6, 7];
var ct = GostCipher.encrypt(pt, key);
var secret = GostCipher.decrypt(ct, key);
if (secret != pt) {
  alert('gost cipher failed');
}
```
### Hash
There are two public functions, both take a string and return its hash as string. Functions are:
 - *hash* (standard version)
 - *hashCrypto* (CryptoPro version)
``` html
<script type='text/javascript' src='gost_hash.js'></script>
```
``` js
console.log(GostHash.hashCrypto('')); // Write the gost-crypto hash of the empty string
console.log(GostHash.hash('hello world'));  // Write the gost hash of the 'hello wordl' string
```
*Notes*:
 - Hash and cipher are independent, so you can use only one if needed
 - See [test file](test/gost_test.html) for code example

## Compatibility
You can find a richer and better alternative cryptographic libraries for your site\
But you won't find many solutions compliant with **ECMAScript 3**\
RSS has been tested with most modern browsers down to **MSIE7**\
so you shouldn't have any compatibility issues!

## Security
Short explanation: you can trust

Long explanation:

Cipher is considered *deeply flawed*, and known attacks are much better than brute-force, **but** still require a lot of resources.\
For further details and references see links on [wikipedia page](https://en.wikipedia.org/wiki/GOST_(block_cipher)) in section *Cryptanalysis of GOST*

Hash algorithm is considered broken, but again the efforts required are far from practical.\
See details in [this paper](https://doi.org/10.1007%2F978-3-540-85174-5_10)
