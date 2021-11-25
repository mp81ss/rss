// Taken from https://github.com/ridhb/-GOST-28147-8/blob/master/gost.java
// Ported to javascript by mp81ss on 02 NOV 2021 with sbox from RFC 8891

var GostCipher = (function() {
'use strict';

    var GOST_KEY_LEN = 8;
    var GOST_BLOCK_LEN = 2;

    var k8 = [12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1];
    var k7 = [6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15];
    var k6 = [11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0];
    var k5 = [12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11];
    var k4 = [7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12];
    var k3 = [5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0];
    var k2 = [8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7];
    var k1 = [1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2];

    var k87 = [198, 200, 194, 195, 201, 202, 197, 204, 193, 206, 196, 199, 203, 205,
               192, 207, 70, 72, 66, 67, 73, 74, 69, 76, 65, 78, 68, 71, 75, 77, 64,
               79, 102, 104, 98, 99, 105, 106, 101, 108, 97, 110, 100, 103, 107, 109,
               96, 111, 38, 40, 34, 35, 41, 42, 37, 44, 33, 46, 36, 39, 43, 45, 32,
               47, 166, 168, 162, 163, 169, 170, 165, 172, 161, 174, 164, 167, 171,
               173, 160, 175, 86, 88, 82, 83, 89, 90, 85, 92, 81, 94, 84, 87, 91, 93,
               80, 95, 182, 184, 178, 179, 185, 186, 181, 188, 177, 190, 180, 183, 187,
               189, 176, 191, 150, 152, 146, 147, 153, 154, 149, 156, 145, 158, 148, 151,
               155, 157, 144, 159, 230, 232, 226, 227, 233, 234, 229, 236, 225, 238, 228,
               231, 235, 237, 224, 239, 134, 136, 130, 131, 137, 138, 133, 140, 129, 142,
               132, 135, 139, 141, 128, 143, 214, 216, 210, 211, 217, 218, 213, 220, 209,
               222, 212, 215, 219, 221, 208, 223, 118, 120, 114, 115, 121, 122, 117, 124,
               113, 126, 116, 119, 123, 125, 112, 127, 6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4,
               7, 11, 13, 0, 15, 54, 56, 50, 51, 57, 58, 53, 60, 49, 62, 52, 55, 59, 61,
               48, 63, 246, 248, 242, 243, 249, 250, 245, 252, 241, 254, 244, 247, 251,
               253, 240, 255, 22, 24, 18, 19, 25, 26, 21, 28, 17, 30, 20, 23, 27, 29, 16, 31];

    var k65 = [188, 184, 178, 177, 189, 180, 191, 182, 183, 176, 186, 181, 179,
               190, 185, 187, 60, 56, 50, 49, 61, 52, 63, 54, 55, 48, 58, 53, 51,
               62, 57, 59, 92, 88, 82, 81, 93, 84, 95, 86, 87, 80, 90, 85, 83, 94,
               89, 91, 140, 136, 130, 129, 141, 132, 143, 134, 135, 128, 138, 133,
               131, 142, 137, 139, 44, 40, 34, 33, 45, 36, 47, 38, 39, 32, 42, 37,
               35, 46, 41, 43, 252, 248, 242, 241, 253, 244, 255, 246, 247, 240, 250,
               245, 243, 254, 249, 251, 172, 168, 162, 161, 173, 164, 175, 166, 167,
               160, 170, 165, 163, 174, 169, 171, 220, 216, 210, 209, 221, 212, 223,
               214, 215, 208, 218, 213, 211, 222, 217, 219, 236, 232, 226, 225, 237,
               228, 239, 230, 231, 224, 234, 229, 227, 238, 233, 235, 28, 24, 18, 17,
               29, 20, 31, 22, 23, 16, 26, 21, 19, 30, 25, 27, 124, 120, 114, 113,
               125, 116, 127, 118, 119, 112, 122, 117, 115, 126, 121, 123, 76, 72,
               66, 65, 77, 68, 79, 70, 71, 64, 74, 69, 67, 78, 73, 75, 204, 200, 194,
               193, 205, 196, 207, 198, 199, 192, 202, 197, 195, 206, 201, 203, 156,
               152, 146, 145, 157, 148, 159, 150, 151, 144, 154, 149, 147, 158, 153,
               155, 108, 104, 98, 97, 109, 100, 111, 102, 103, 96, 106, 101, 99, 110,
               105, 107, 12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11];

    var k43 = [117, 125, 127, 118, 121, 114, 124, 122, 123, 119, 120, 113, 116,
               115, 126, 112, 245, 253, 255, 246, 249, 242, 252, 250, 251, 247,
               248, 241, 244, 243, 254, 240, 85, 93, 95, 86, 89, 82, 92, 90, 91,
               87, 88, 81, 84, 83, 94, 80, 165, 173, 175, 166, 169, 162, 172, 170,
               171, 167, 168, 161, 164, 163, 174, 160, 133, 141, 143, 134, 137,
               130, 140, 138, 139, 135, 136, 129, 132, 131, 142, 128, 21, 29, 31,
               22, 25, 18, 28, 26, 27, 23, 24, 17, 20, 19, 30, 16, 101, 109, 111,
               102, 105, 98, 108, 106, 107, 103, 104, 97, 100, 99, 110, 96, 213,
               221, 223, 214, 217, 210, 220, 218, 219, 215, 216, 209, 212, 211,
               222, 208, 5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0,
               149, 157, 159, 150, 153, 146, 156, 154, 155, 151, 152, 145, 148,
               147, 158, 144, 53, 61, 63, 54, 57, 50, 60, 58, 59, 55, 56, 49, 52,
               51, 62, 48, 229, 237, 239, 230, 233, 226, 236, 234, 235, 231, 232,
               225, 228, 227, 238, 224, 181, 189, 191, 182, 185, 178, 188, 186,
               187, 183, 184, 177, 180, 179, 190, 176, 69, 77, 79, 70, 73, 66,
               76, 74, 75, 71, 72, 65, 68, 67, 78, 64, 37, 45, 47, 38, 41, 34,
               44, 42, 43, 39, 40, 33, 36, 35, 46, 32, 197, 205, 207, 198, 201,
               194, 204, 202, 203, 199, 200, 193, 196, 195, 206, 192];
    
    var k21 = [129, 135, 142, 141, 128, 133, 136, 131, 132, 143, 138, 134, 137,
               140, 139, 130, 225, 231, 238, 237, 224, 229, 232, 227, 228, 239,
               234, 230, 233, 236, 235, 226, 33, 39, 46, 45, 32, 37, 40, 35, 36,
               47, 42, 38, 41, 44, 43, 34, 81, 87, 94, 93, 80, 85, 88, 83, 84,
               95, 90, 86, 89, 92, 91, 82, 97, 103, 110, 109, 96, 101, 104, 99,
               100, 111, 106, 102, 105, 108, 107, 98, 145, 151, 158, 157, 144,
               149, 152, 147, 148, 159, 154, 150, 153, 156, 155, 146, 17, 23,
               30, 29, 16, 21, 24, 19, 20, 31, 26, 22, 25, 28, 27, 18, 193,
               199, 206, 205, 192, 197, 200, 195, 196, 207, 202, 198, 201, 204,
               203, 194, 241, 247, 254, 253, 240, 245, 248, 243, 244, 255, 250,
               246, 249, 252, 251, 242, 65, 71, 78, 77, 64, 69, 72, 67, 68, 79,
               74, 70, 73, 76, 75, 66, 177, 183, 190, 189, 176, 181, 184, 179,
               180, 191, 186, 182, 185, 188, 187, 178, 1, 7, 14, 13, 0, 5, 8, 3,
               4, 15, 10, 6, 9, 12, 11, 2, 209, 215, 222, 221, 208, 213, 216,
               211, 212, 223, 218, 214, 217, 220, 219, 210, 161, 167, 174, 173,
               160, 165, 168, 163, 164, 175, 170, 166, 169, 172, 171, 162, 49,
               55, 62, 61, 48, 53, 56, 51, 52, 63, 58, 54, 57, 60, 59, 50, 113,
               119, 126, 125, 112, 117, 120, 115, 116, 127, 122, 118, 121, 124, 123, 114];

    function getRandomValues(values) {
        var len = values.length;

        if (values && (len > 0)) {
            var crypto =  window.crypto || window.msCrypto || window.msrCrypto;
            var i;

            if (crypto) {
                var typedValues = new Int32Array(len);

                crypto.getRandomValues(typedValues);
                for (i = 0; i < len; i += 1) {
                    values[i] = typedValues[i];
                }
            }
            else {
                for (i = 0; i < len; i += 1) {
                    values[i] = (Math.random() * (Math.pow(2, 32) - 1)) | 0;
                }
            }
        }
    }

    function f(x){
        x = (k87[((x >>> 24) & 255)] << 24 | k65[((x >>> 16) & 255)] << 16 |
             k43[((x >>> 8) & 255)] <<  8 | k21[(x & 255)]);
        return ((x << 11) | (x >>> 21));
    }

    function encryptBlock(input, output, key) {
        var n1 = input[0];
        var n2 = input[1];

        n2 ^= f((n1+key[0]));
        n1 ^= f((n2+key[1]));
        n2 ^= f((n1+key[2]));
        n1 ^= f((n2+key[3]));
        n2 ^= f((n1+key[4]));
        n1 ^= f((n2+key[5]));
        n2 ^= f((n1+key[6]));
        n1 ^= f((n2+key[7]));

        n2 ^= f((n1+key[0]));
        n1 ^= f((n2+key[1]));
        n2 ^= f((n1+key[2]));
        n1 ^= f((n2+key[3]));
        n2 ^= f((n1+key[4]));
        n1 ^= f((n2+key[5]));
        n2 ^= f((n1+key[6]));
        n1 ^= f((n2+key[7]));

        n2 ^= f((n1+key[0]));
        n1 ^= f((n2+key[1]));
        n2 ^= f((n1+key[2]));
        n1 ^= f((n2+key[3]));
        n2 ^= f((n1+key[4]));
        n1 ^= f((n2+key[5]));
        n2 ^= f((n1+key[6]));
        n1 ^= f((n2+key[7]));

        n2 ^= f((n1+key[7]));
        n1 ^= f((n2+key[6]));
        n2 ^= f((n1+key[5]));
        n1 ^= f((n2+key[4]));
        n2 ^= f((n1+key[3]));
        n1 ^= f((n2+key[2]));
        n2 ^= f((n1+key[1]));
        n1 ^= f((n2+key[0]));
        
        /* There is no swap after the last round */
        output[0] = n2;
        output[1] = n1;
    }

    function decryptBlock(input, output, key) {
        var n1 = input[0];
        var n2 = input[1];

        n2 ^= f((n1+key[0]));
        n1 ^= f((n2+key[1]));
        n2 ^= f((n1+key[2]));
        n1 ^= f((n2+key[3]));
        n2 ^= f((n1+key[4]));
        n1 ^= f((n2+key[5]));
        n2 ^= f((n1+key[6]));
        n1 ^= f((n2+key[7]));

        n2 ^= f((n1+key[7]));
        n1 ^= f((n2+key[6]));
        n2 ^= f((n1+key[5]));
        n1 ^= f((n2+key[4]));
        n2 ^= f((n1+key[3]));
        n1 ^= f((n2+key[2]));
        n2 ^= f((n1+key[1]));
        n1 ^= f((n2+key[0]));

        n2 ^= f((n1+key[7]));
        n1 ^= f((n2+key[6]));
        n2 ^= f((n1+key[5]));
        n1 ^= f((n2+key[4]));
        n2 ^= f((n1+key[3]));
        n1 ^= f((n2+key[2]));
        n2 ^= f((n1+key[1]));
        n1 ^= f((n2+key[0]));

        n2 ^= f((n1+key[7]));
        n1 ^= f((n2+key[6]));
        n2 ^= f((n1+key[5]));
        n1 ^= f((n2+key[4]));
        n2 ^= f((n1+key[3]));
        n1 ^= f((n2+key[2]));
        n2 ^= f((n1+key[1]));
        n1 ^= f((n2+key[0]));

        output[0] = n2;
        output[1] = n1;
    }

    function handleKey(key) {
        var i, k;

        if ((typeof key) == 'string') {
            var re = /^(0[xX])?[0-9A-Fa-f]{64}$/;

            if ((re.exec(key) === null)) {
                throw 'Key as hexadecimal string must have size equal to 64';
            }

            k = new Array(8);
            for (i = 0; i < key.length; i += 8) {
                k[i] = parseInt(key.substring(i, i + 8), 16);
            }
        }
        else if (key && key.length && (key.length == GOST_KEY_LEN)) {
            for (i = 0; i < GOST_KEY_LEN; i += 1) {
                if ((typeof key[i]) != 'number') {
                    throw 'Key as array must have integers as elements';
                }
            }
            k = key;
        }
        else {
            throw 'Missing/invalid key: must be an hex string with size equal to 64 '
                  + 'or an array of 8 integers';
        }

        return k;
    }

    function arrayToHex(arr) {
        var hexStr = '';

        for (var i = 0, n = arr.length; i < n; i += 1) {
            var nStr = Number((arr[i] & 0xFFFFFFFF) >>> 0).toString(16);

            while (nStr.length < 8) {
                nStr = '0' + nStr;
            }
            hexStr += nStr;
        }

        return hexStr;
    }

    function encrypt(pt, key) {
        if ((typeof pt) != 'string') {
            throw 'Plain text must be a string';
        }

        var k = handleKey(key);
        var len  = pt.length;
        var added = 4 - (len & 3);
        var block = new Array(GOST_BLOCK_LEN);
        var cipherText = new Array(GOST_BLOCK_LEN);
        var ctLen = 2 + (((len + added) / 2) | 0);
        var ct = new Array(ctLen);

        getRandomValues(cipherText);
        ct[0] = cipherText[0];
        ct[1] = cipherText[1];

        for (var i = 0; (len - i) >= 4; i += 4) {
            block[0] = (ct[i >>> 1] & 0xFFFF) ^ pt.charCodeAt(i);
            block[0] |= (((ct[i >>> 1] >>> 16) ^ pt.charCodeAt(i + 1)) << 16);
            block[1] = (ct[(i >>> 1) + 1] & 0xFFFF) ^ pt.charCodeAt(i + 2);
            block[1] |= (((ct[(i >>> 1) + 1] >>> 16) ^ pt.charCodeAt(i + 3)) << 16);
            encryptBlock(block, cipherText, k);
            ct[(i >>> 1) + 2] = cipherText[0];
            ct[(i >>> 1) + 3] = cipherText[1];
        }

        switch (added)
        {
          case 1:
            block[0] = (pt.charCodeAt(len - 2) << 16) | pt.charCodeAt(len - 3);
            block[1] = pt.charCodeAt(len - 1) | (added << 16);
            break;

          case 2:
            block[0] = (pt.charCodeAt(len - 1) << 16) | pt.charCodeAt(len - 2);
            block[1] = (added << 16) | added;
            break;

          case 3:
            block[0] = pt.charCodeAt(len - 1) | (added << 16);
            block[1] = (added << 16) | added;
            break;

          case 4:
            block[0] = (added << 16) | added;
            block[1] = block[0];
            break;
        }

        block[0] ^= ct[ctLen - 4];
        block[1] ^= ct[ctLen - 3];
        encryptBlock(block, cipherText, k);
        ct[ctLen - 2] = cipherText[0];
        ct[ctLen - 1] = cipherText[1];

        return arrayToHex(ct);
    }

    function decrypt(ct, key) {
        if ((typeof ct) != 'string') {
            throw 'Cipher text must be a string';
        }

        var k = handleKey(key);
        var len = ct.length;
        var re = /^[0-9A-Fa-f]{32,}$/;

        if ((re.exec(ct) === null) || ((len & 0xF) != 0)) {
            throw 'Invalid cipher text was passed';
        }

        var cipherText = new Array(GOST_BLOCK_LEN);
        var block = new Array(GOST_BLOCK_LEN);
        var secret = new Array(GOST_BLOCK_LEN);
        var plainText = String();

        cipherText[0] = parseInt(ct.slice(0, 8), 16);
        cipherText[1] = parseInt(ct.slice(8, 16), 16);

        for (var i = 16; i < (len - 16); i += 16) {
            block[0] = parseInt(ct.slice(i, i + 8), 16);
            block[1] = parseInt(ct.slice(i + 8, i + 16), 16);
            decryptBlock(block, secret, k);
            secret[0] ^= cipherText[0];
            secret[1] ^= cipherText[1];
            cipherText[0] = block[0];
            cipherText[1] = block[1];
            plainText += String.fromCharCode(secret[0] & 0xFFFF) +
                         String.fromCharCode(secret[0] >>> 16) +
                         String.fromCharCode(secret[1] & 0xFFFF) +
                         String.fromCharCode(secret[1] >>> 16);
        }

        block[0] = parseInt(ct.slice(len - 16, len - 8), 16);
        block[1] = parseInt(ct.slice(len - 8, len), 16);
        decryptBlock(block, secret, k);
        secret[1] ^= cipherText[1];

        var remaining = 4 - (secret[1] >>> 16);

        if (remaining > 0) {
            secret[0] ^= cipherText[0];

            var addStr = String.fromCharCode(secret[0] & 0xFFFF);

            if (remaining > 1) {
                addStr += String.fromCharCode(secret[0] >>> 16);
                if (remaining == 3) {
                    addStr += String.fromCharCode(secret[1] & 0xFFFF);
                }
            }

            plainText += addStr;
        }

        return plainText;
    }
/*
    function testBblock(iterations) {
        var pt = new Array(2);
        var ct = new Array(2);
        var secret = new Array(2);
        var key = new Array(8);
        
        for (var i = 0; i < iterations; i += 1) {
            getRandomValues(pt);
            getRandomValues(key);
            encryptBlock(pt, ct, key);
            decryptBlock(ct, secret, key);
            if ((pt.length != 2) || (ct.length != 2) || (secret.length != 2)
                || (secret[0] != pt[0]) || (secret[1] != pt[1]))
            {
                alert('Gost cipher test failed');
                throw 'Gost cipher test failed';
            }
        }
    }
*/
return {
    encrypt: encrypt,
    decrypt: decrypt
};

}());
