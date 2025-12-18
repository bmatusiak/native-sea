
// require("gun/lib/mobile");
// var Gun = require("gun");
// require("gun/sea");
// var SEA = Gun.SEA;


import Aes from 'react-native-aes-crypto';//for faster pbkdf2  *node-forge=slow
import * as Crypto from 'expo-crypto';//randomBytes!
import elliptic from 'elliptic';//pair/secret/sign/verify

(function (window) {
    var SEA = window.SEA || {};

    var forge = require('node-forge');// encrypt/decrypt
    forge.options.usePureJavaScript = true;

    var EC = elliptic.ec;
    var ECDH = new EC('p256');
    var ECDSA = new EC('p256');

    // setTimeout(function () {
    //     (async () => {
    //         var gun_pair = await doPair();
    //         var $msg = await doWork("data", "salty");
    //         if ($msg) console.log("doWork", $msg)
    //         var aeskey = await doDerive(gun_pair.epub, gun_pair);
    //         if (aeskey) console.log("doDerive", aeskey);
    //         var sig = await doSign($msg, gun_pair);
    //         if (sig) console.log("doSign", sig);
    //         var ver = await doVerify(sig, gun_pair.pub);
    //         if (ver) console.log("doVerify", ver);
    //         var enc = await doEncrypt($msg, aeskey);
    //         if (enc) console.log("doEncrypt", enc);
    //         var dec = await doDecrypt(enc, aeskey);
    //         if (dec) console.log("doDecrypt", dec);
    //     })()
    // }, 1000);


    function genKeyPair() {
        var ec = new EC('p256');
        var pair = ec.genKeyPair();
        var pub = pair.getPublic();
        var x = pub.getX().toBuffer();
        var y = pub.getY().toBuffer();
        var priv = pair.getPrivate().toBuffer();
        pub = arrayBufToBase64UrlEncode(x) + "." + arrayBufToBase64UrlEncode(y);
        priv = arrayBufToBase64UrlEncode(priv);
        return { pub, priv, epub: pub, epriv: priv };
    }

    async function doPair() {
        var { pub, priv } = genKeyPair();
        var { epub, epriv } = genKeyPair();
        return { pub, priv, epub, epriv };
    }
    SEA.pair = doPair;
    //EAS/PBKDF2
    async function doWork(data, pair, cb, opt) {
        var u;
        var salt = (pair || {}).epub || pair; // epub not recommended, salt should be random!
        opt = opt || {};
        if (salt instanceof Function) {
            cb = salt;
            salt = u;
        }
        data = (typeof data == 'string') ? data : await shim.stringify(data);
        if ('sha' === (opt.name || '').toLowerCase().slice(0, 3)) {
            var rsha = shim.Buffer.from(await sha256_n(data), 'binary').toString(opt.encode || 'base64')
            if (cb) { try { cb(rsha) } catch (e) { console.log(e) } }
            return rsha;
        }
        salt = salt || shim.random(9);
        var S = { pbkdf2: { hash: { name: 'SHA-256' }, iter: 100000, ks: 64 } };
        var work = await Aes.pbkdf2(data, salt, S.pbkdf2.iter, S.pbkdf2.ks * 8, "sha256");
        // var w = await SEA.work(data, salt);//{hash: {name : 'SHA-256'}, iter: 100000, ks: 64};

        data = shim.random(data.length)  // Erase data in case of passphrase
        var r = Buffer.from(work, "hex").toString(opt.encode || 'base64');
        if (cb) { try { cb(r) } catch (e) { console.log(e) } }
        return r;
    }
    SEA.work = doWork;

    async function doDerive(key, pair, cb, opt) {
        opt = opt || {};
        if (!pair || !pair.epriv || !pair.epub) {
            if (!SEA.I) { throw 'No secret mix.' }
            pair = await SEA.I(null, { what: key, how: 'secret', why: opt.why });
        }
        var pub = key.epub || key;
        // var epub = pair.epub;
        var epriv = pair.epriv

        var parsedPair = u8(Buffer.concat([
            Buffer.from([4]),
            arrayBufToBase64UrlDecode(pub.split(".")[0]),
            arrayBufToBase64UrlDecode(pub.split(".")[1])
        ]))
        var key = ECDH.keyFromPrivate(arrayBufToBase64UrlDecode(epriv));
        var derived = arrayBufToBase64UrlEncode(key.derive(ECDH.keyFromPublic(parsedPair).getPublic()).toBuffer())
        var r = derived;
        if (cb) { try { cb(r) } catch (e) { console.log(e) } }
        return r;
    }
    SEA.secret = doDerive;

    async function doVerify(data, pair, cb, opt) {
        var u;
        var json = await shim.S.parse(data);
        if (false === pair) { // don't verify!
            var raw = await shim.S.parse(json.m);
            if (cb) { try { cb(raw) } catch (e) { console.log(e) } }
            return raw;
        }
        opt = opt || {};
        // SEA.I // verify is free! Requires no user permission.
        var pub = pair.pub || pair;

        var parsedPair = u8(Buffer.concat([
            Buffer.from([4]),
            arrayBufToBase64UrlDecode(pub.split(".")[0]),
            arrayBufToBase64UrlDecode(pub.split(".")[1])
        ]))
        var key = ECDSA.keyFromPublic(u8(parsedPair));
        // var parsedData = JSON.parse(data.substring(3, data.length));
        var dataHash = await sha256_n(await sha256_n(json.m));
        var sig = u8(Buffer.from(json.s, "base64"))
        var r = sig.slice(0, 32);
        var s = sig.slice(32);
        var sig_ = {
            r: u8(r),
            s: u8(s)
        }
        var check = key.verify(dataHash, sig_)
        var r = check ? await shim.S.parse(json.m) : u;
        if (!check) { throw "Signature did not match." }
        if (cb) { try { cb(r) } catch (e) { console.log(e) } }
        return r;
    }
    SEA.verify = doVerify;

    async function doSign(data, pair, cb, opt) { // console.log("doSign")
        var u;
        opt = opt || {};
        if (!(pair || opt).priv) {
            if (!SEA.I) { throw 'No signing key.' }
            pair = await SEA.I(null, { what: data, how: 'sign', why: opt.why });
        }
        if (u === data) { throw '`undefined` not allowed.' }
        var json = await shim.S.parse(data);
        var check = opt.check = opt.check || json;
        if (SEA.verify && SEA.opt.check(check)) return;
        // var pub = pair.pub;
        var priv = pair.priv;

        var key = ECDSA.keyFromPrivate(arrayBufToBase64UrlDecode(priv));
        var sig = key.sign(await sha256_n(await sha256_n(json)));
        var r = sig.r.toBuffer();
        var s = sig.s.toBuffer();
        var rs = Buffer.concat([r, s]);
        sig = { m: json, s: rs.toString("base64") };
        if (!opt.raw) { sig = 'SEA' + await shim.stringify(sig) }
        if (cb) { try { cb(sig) } catch (e) { console.log(e) } }
        return sig;
    }
    SEA.sign = doSign;

    async function doEncrypt(data, pair, cb, opt) { // decrypt node-forge message with sea
        var u;
        opt = opt || {};
        var key = (pair || opt).epriv || pair;
        if (u === data) { throw '`undefined` not allowed.' }
        if (!key) {
            if (!SEA.I) { throw 'No encryption key.' }
            pair = await SEA.I(null, { what: data, how: 'encrypt', why: opt.why });
            key = pair.epriv || pair;
        }
        var msg = (typeof data == 'string') ? data : await shim.stringify(data);
        var iv = forge.random.getBytesSync(15);
        var salt = Buffer.from(forge.util.bytesToHex(forge.random.getBytesSync(9)), "hex");
        var tkey = key + bytes2string(salt)
        var pKey = Array.from(await sha256_utf8_n(tkey));
        var cipher = forge.cipher.createCipher('AES-GCM', pKey);
        cipher.start({
            iv: iv, // should be a 12-byte binary-encoded string or byte buffer
            tagLength: 128
        });
        cipher.update(forge.util.createBuffer(msg));
        cipher.finish();
        var encrypted = cipher.output.getBytes();
        var tag = cipher.mode.tag.getBytes();
        var ct = Buffer.concat([
            Buffer.from(forge.util.bytesToHex(encrypted), "hex"),
            Buffer.from(forge.util.bytesToHex(tag), "hex")
        ])
        var r = {
            ct: ct.toString("base64"),
            s: salt.toString("base64"),
            iv: Buffer.from(forge.util.bytesToHex(iv), "hex").toString("base64")
        }
        if (!opt.raw) { r = 'SEA' + await shim.stringify(r) }
        if (cb) { try { cb(r) } catch (e) { console.log(e) } }
        return r;
    }
    SEA.encrypt = doEncrypt;

    async function doDecrypt(data, pair, cb, opt) {
        opt = opt || {};
        var key = (pair || opt).epriv || pair;
        if (!key) {
            if (!SEA.I) { throw 'No decryption key.' }
            pair = await SEA.I(null, { what: data, how: 'decrypt', why: opt.why });
            key = pair.epriv || pair;
        }
        var json = await shim.S.parse(data);
        var tkey = key + bytes2string(Buffer.from(json.s, "base64"))
        var pKey = Array.from(await sha256_utf8_n(tkey));
        var ctx = u8(Buffer.from(json.ct, "base64"));
        var tag = ctx.slice(ctx.length - 16, ctx.length);
        var ct = ctx.slice(0, ctx.length - 16);
        var decipher = forge.cipher.createDecipher('AES-GCM', pKey);
        decipher.start({
            iv: Buffer.from(json.iv, "base64"),
            tag: tag
        });
        decipher.update(forge.util.createBuffer(ct));
        var pass = decipher.finish();
        if (!pass) { throw "Could not decrypt" }
        var r = decipher.output.data;
        if (cb) { try { cb(r) } catch (e) { console.log(e) } }
        return r;
    };
    SEA.decrypt = doDecrypt;

    //------------

    function u8(a) {
        return new Uint8Array(a);
    }
    function bytes2string(bytes) {
        var ret = Array.from(bytes).map(function chr(c) {
            return String.fromCharCode(c);
        }).join('');
        return ret;
    }
    function string2bytes(s) {
        var len = s.length;
        var bytes = [];
        for (var i = 0; i < len; i++) bytes.push(0);
        for (var i = 0; i < len; i++) bytes[i] = s.charCodeAt(i);
        return bytes;
    };
    function hexStrToDec(hexStr) {
        return ~~(new Number('0x' + hexStr).toString(10));
    }
    function sha256(s) {
        var b2s = !(typeof s == "string")
        var md = forge.md.sha256.create();
        md.update(b2s ? bytes2string(s) : s);
        var h = md.digest().toHex();
        var hash = Buffer.from(h.match(/.{2}/g).map(hexStrToDec));
        // console.log("-", buff2hex(hash));
        return hash;
    }
    function sha256_utf8(s) {
        var md = forge.md.sha256.create();
        md.update(s, 'utf8');
        var hash = Buffer.from(md.digest().toHex().match(/.{2}/g).map(hexStrToDec));
        // var hash = Buffer.from(Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, s).match(/.{2}/g).map(hexStrToDec));
        return hash;
    }
    async function sha256_n(s) {
        var s2b = (typeof s == "string")
        const array = new Uint8Array(s2b ? string2bytes(s) : s);
        const digest = await Crypto.digest(Crypto.CryptoDigestAlgorithm.SHA256, array);
        return u8(digest)
    }
    async function sha256_utf8_n(s) {
        var digest = await Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, s);
        var hash = Buffer.from(digest.match(/.{2}/g).map(hexStrToDec));
        return hash;
    }
    function u2f_unb64(s) {
        s = s.replace(/-/g, '+').replace(/_/g, '/');
        return atob(s + '==='.slice((s.length + 3) % 4));
    }
    function u2f_b64(s) {
        return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
    function arrayBufToBase64UrlEncode(buf) {
        var binary = '';
        var bytes = new Uint8Array(buf);
        for (var i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary).replace(/\//g, '_').replace(/=/g, '').replace(/\+/g, '-');
    }
    function arrayBufToBase64UrlDecode(ba64) {
        var binary = u2f_unb64(ba64);
        var bytes = [];
        for (var i = 0; i < binary.length; i++) {
            bytes.push(binary.charCodeAt(i));
        }

        return new Uint8Array(bytes);
    }
    var shim = { Buffer }
    shim.crypto = window.crypto || window.msCrypto
    shim.subtle = (shim.crypto || o).subtle || (shim.crypto || o).webkitSubtle;
    shim.TextEncoder = window.TextEncoder;
    shim.TextDecoder = window.TextDecoder;
    shim.random = (len) => shim.Buffer.from(shim.crypto.getRandomValues(new Uint8Array(shim.Buffer.alloc(len))));
    shim.parse = function (t, r) {
        return new Promise(function (res, rej) {
            JSON.parseAsync(t, function (err, raw) { err ? rej(err) : res(raw) }, r);
        })
    }
    shim.stringify = function (v, r, s) {
        return new Promise(function (res, rej) {
            JSON.stringifyAsync(v, function (err, raw) { err ? rej(err) : res(raw) }, r, s);
        })
    }
    shim.S = {};
    shim.S.parse = async function p(t) {
        try {
            var yes = (typeof t == 'string');
            if (yes && 'SEA{' === t.slice(0, 4)) { t = t.slice(3) }
            return yes ? await shim.parse(t) : t;
        } catch (e) { }
        return t;
    }

    window.SEA = SEA;
})(global || window);