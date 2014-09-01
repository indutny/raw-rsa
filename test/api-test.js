var assert = require('assert');
var rsa = require('../');

var key = require('fs').readFileSync(__dirname + '/keys/key.pem');

describe('raw-rsa', function() {
  it('should encrypt/decrypt data', function() {
    var priv = new rsa.Key(key);
    var pad = rsa.RSA_PKCS1_PADDING;

    var out = new Buffer(priv.size());
    var r = priv.publicEncrypt(out, new Buffer('wow wow, wtf'), pad);

    var r = priv.privateDecrypt(out, out.slice(0, r), pad);

    assert.equal(out.slice(0, r).toString(), 'wow wow, wtf');
  });
});
