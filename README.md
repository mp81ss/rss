# Russian-secured-site

## Introduction
It is a *javascript* cryptography library offering a symmetric cipher and a hashing algorithm\
The encryption algorithm is [**GOST 28147-89**](https://en.wikipedia.org/wiki/GOST_(block_cipher))\
The hash algorithm is [**GOST R 34.11-94**](https://en.wikipedia.org/wiki/GOST_(hash_function)) in two variants: *standard* and *crypto*, see details below

## Details
The cipher (called *magma*) is implemented with updated sbox from **RFC 8891**

The hash function is available in two variants:
 - Standard variant (with sbox from **RFC 4351**), commonly called *GOST*
 - The *CryptoPro* variant is implemented with sbox suggested by [CryptoPro company](https://www.cryptopro.ru) in **RFC 4357**, commonly called *gost-crypto*

## Installation/Usage
``` html
<script type='text/javascript' src='gost_hash.js'></script>
<script type='text/javascript' src='gost.js'></script>
```
Hash and cipher are independent, so you can use only one if needed

## Compatibility
You can find a lots of richer and better alternative cryptographic libraries for your site\
But you won't find a lot of solutions compliant with for **ECMAScript 3**\
RSS has been tested with most modern browsers down to **MSIE7**\
so you shouldn't have any compatibility issues!

## Security
Short explanation: you can trust

Long explanation:

Cipher is considered *deeply flawed*, and known attacks are much better than brute-force, **but** still require a lot of resources.\
For further details and references see links on [wikipedia page](https://en.wikipedia.org/wiki/GOST_(block_cipher)) in section *Cryptanalysis of GOST*

Hash algorithm is considered broken, but again the efforts required are far from practical.\
See details in [this paper](https://doi.org/10.1007%2F978-3-540-85174-5_10)
