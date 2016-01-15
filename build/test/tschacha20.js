'use strict';
var chai = require('chai');
var chacha20_1 = require('../src/chacha20');
var assert = require('assert');
describe('typescript test chacha20', function () {
    it('reference tests', function () {
        var key = new Buffer(32).fill(0);
        var nonce = new Buffer(8).fill(0);
        var chacha20 = new chacha20_1.Chacha20(key, nonce);
        var data = "\0\0\0\0\0\0\0\0\0"; // 9
        var out = chacha20.update(new Buffer(data));
        chai.expect(out.toString('hex')).to.be.equal("76b8e0ada0f13d9040");
        chacha20 = new chacha20_1.Chacha20(key, nonce);
        chai.expect(chacha20.update(out).toString()).to.be.equal(data);
        key.fill(0xff);
        nonce.fill(0xff);
        chacha20 = new chacha20_1.Chacha20(key, nonce);
        var ff = new Buffer(9).fill(0xff);
        out = chacha20.update(ff);
        chai.expect(out.toString('hex')).to.be.equal("2640c09431912f4abd");
        chacha20 = new chacha20_1.Chacha20(key, nonce);
        chai.expect(chacha20.update(out).toString("hex")).to.be.equal(ff.toString("hex"));
    });
    it('test counter', function () {
        // http://www.example-code.com/vbscript/chacha20.asp
        var keyHex = "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0";
        var vbKey = new Buffer(keyHex, 'hex');
        var ivHex = "000000000000000000000002";
        var vbIv = new Buffer(ivHex, 'hex');
        var chacha20 = new chacha20_1.Chacha20(vbKey, vbIv, 42);
        var plaintext = "'Twas brillig, and the slithy toves\nDid gyre and gimble in the wabe:\nAll mimsy were the borogoves,\nAnd the mome raths outgrabe.";
        var cipherText = chacha20.update(new Buffer(plaintext));
        assert.deepEqual(cipherText, new Buffer('62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1', 'hex'));
    });
});
