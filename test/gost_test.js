'use strict';

function getRandomValues(values) {
  if (values && values.length && (values.length > 0)) {
    var crypto = window.crypto || window.msCrypto || window.msrCrypto;
    var len = values.length;
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

function testSingle(pt, key) {
  var gost = GostCipher;
  var ct = gost.encrypt(pt, key);
  var secret = gost.decrypt(ct, key);

  if (pt != secret) {
    var errMsg = 'ГОСТ test failed with string pt of length ' +
        Number(pt.length).toString() + ' and secret of length ' +
        Number(secret.length).toString();
    alert(errMsg);
    throw errMsg;
  }
}

function gostTest(iterations, maxLen) {
  var pt = '';
  var key;

  for (var i = 0; i < iterations; i += 1) {
    var len = (Math.random() * maxLen) | 0;

    for (var j = 0; j < len; j += 1) {
      var code = (Math.random() * 0xD7FF) | 0;
      pt += String.fromCharCode(code);
    }

    key = new Array(8);
    getRandomValues(key);
    if ((i & 1) == 0) {
      var keyStr = '';

      for (var ki = 0; ki < 8; ki += 1) {
        var nStr = Number((key[ki] & 0xFFFFFFFF) >>> 0).toString(16);

        while (nStr.length < 8) {
          nStr = '0' + nStr;
        }
        keyStr += nStr;
      }
      key = keyStr;
    }

    testSingle(pt, key);
  }
}
