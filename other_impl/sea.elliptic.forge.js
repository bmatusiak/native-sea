var forge = require('node-forge');
forge.options.usePureJavaScript = true;

var elliptic = require('elliptic');

function u8(a) {
    return new Uint8Array(a);
}

var Gun = require("gun");
require("gun/sea/index");
var SEA = Gun.SEA;


var EC = elliptic.ec;
var ECDH = new EC('p256');
var ECDSA = new EC('p256');

var ec_pair = ECDSA.genKeyPair();


var aeskey; // = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

var gun_pair;

var $msg = "data";

(async () => {
    gun_pair = await doPair();
    aeskey = await doDerive();
    await doSign();
    await doEncrypt();
    await doDecrypt();
    await doVerify();
})();

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
    var {
        pub,
        priv
    } = genKeyPair();
    var {
        epub,
        epriv
    } = genKeyPair();
    var pair = {
        pub,
        priv,
        epub,
        epriv
    }
    // console.log(pair);
    return pair;
}

async function doDerive() {

    var secret = await SEA.secret(gun_pair.epub, gun_pair)

    var parsedPair = u8(Buffer.concat([
        Buffer.from([4]),
        arrayBufToBase64UrlDecode(gun_pair.epub.split(".")[0]),
        arrayBufToBase64UrlDecode(gun_pair.epub.split(".")[1])
    ]))
    // console.log(parsedPair)

    var key = ECDH.keyFromPrivate(arrayBufToBase64UrlDecode(gun_pair.epriv))

    var pubkey = key.getPublic();
    pubkey = u8(Buffer.concat([
        Buffer.from([4]),
        pubkey.getX().toBuffer(),
        pubkey.getY().toBuffer()
    ]));
    // console.log(pubkey)

    var test_secret = arrayBufToBase64UrlEncode(key.derive(ECDH.keyFromPublic(pubkey).getPublic()).toBuffer())

    if (secret == test_secret) {
        console.log("WORKS")
    } else
        console.log("FAIL", secret, test_secret)

    return secret;

}

async function doEncrypt() { // decrypt node-forge message with sea

    var iv = forge.random.getBytesSync(15);
    var salt = Buffer.from(forge.util.bytesToHex(forge.random.getBytesSync(9)), "hex");

    var tkey = aeskey + bytes2string(salt)
    var pKey = Array.from(sha256_utf8(tkey));

    var cipher = forge.cipher.createCipher('AES-GCM', pKey);
    cipher.start({
        iv: iv, // should be a 12-byte binary-encoded string or byte buffer
        tagLength: 128
    });

    cipher.update(forge.util.createBuffer($msg));
    cipher.finish();

    var encrypted = cipher.output.getBytes();
    var tag = cipher.mode.tag.getBytes();

    var ct = Buffer.concat([
        Buffer.from(forge.util.bytesToHex(encrypted), "hex"),
        Buffer.from(forge.util.bytesToHex(tag), "hex")
    ])
    var seaMsg = {
        ct: ct.toString("base64"),
        s: salt.toString("base64"),
        iv: Buffer.from(forge.util.bytesToHex(iv), "hex").toString("base64")
    }

    var enc = "SEA" + JSON.stringify(seaMsg);

    var denc = await SEA.decrypt(enc, aeskey);

    if (denc && denc == $msg) {
        console.log("WORKS")
    } else
        console.log("FAIL")

    // doDecrypt(enc)

}

async function doDecrypt() {
    // decrypt sea message with node-forge
    // return;


    var enc = await SEA.encrypt($msg, aeskey);
    enc = JSON.parse(enc.substring(3, enc.length));

    var tkey = aeskey + bytes2string(Buffer.from(enc.s, "base64"))
    var pKey = Array.from(sha256_utf8(tkey));


    var ctx = u8(Buffer.from(enc.ct, "base64"));
    var tag = ctx.slice(ctx.length - 16, ctx.length);
    var ct = ctx.slice(0, ctx.length - 16);

    var decipher = forge.cipher.createDecipher('AES-GCM', pKey);
    decipher.start({
        iv: Buffer.from(enc.iv, "base64"),
        tag: tag
    });
    decipher.update(forge.util.createBuffer(ct));

    var pass = decipher.finish();

    if (pass && decipher.output.data == $msg) {
        console.log("WORKS")
    } else
        console.log("FAIL")



};


async function doVerify(data) { // console.log("doVerify")

    if (!data)
        data = await SEA.sign($msg, gun_pair);


    // var msg = await SEA.verify(data, gun_pair.pub)
    // console.log(data)
    var parsedPair = u8(Buffer.concat([
        Buffer.from([4]),
        arrayBufToBase64UrlDecode(gun_pair.pub.split(".")[0]),
        arrayBufToBase64UrlDecode(gun_pair.pub.split(".")[1])
    ]))

    var key = ECDSA.keyFromPublic(u8(parsedPair));
    var parsedData = JSON.parse(data.substring(3, data.length));
    var dataHash = sha256(sha256(parsedData.m))
    var sig = u8(Buffer.from(parsedData.s, "base64"))
    var r = sig.slice(0, 32);
    var s = sig.slice(32);
    var sig_ = {
        r: u8(r),
        s: u8(s)
    }

    if (key.verify(dataHash, sig_)) {
        console.log("WORKS")
        return true;
    } else
        console.log("FAIL")



}

async function doSign(data) { // console.log("doSign")

    if (!data)
        data = $msg;


    var key = ECDSA.keyFromPrivate(arrayBufToBase64UrlDecode(gun_pair.priv))

    var sig = key.sign(sha256(sha256(data)));
    var r = sig.r.toBuffer()
    var s = sig.s.toBuffer()
    var rs = Buffer.concat([r, s]);
    sig = "SEA" + JSON.stringify({ m: data, s: rs.toString("base64") })
    // console.log( "r",r);
    // console.log( "s",s)
    // console.log( "rs",rs)

    var verified = await SEA.verify(sig, gun_pair.pub);

    if (verified) {
        console.log("WORKS")
    } else
        console.log("FAIL")



}


function bytes2string(bytes) {
    var ret = Array.from(bytes).map(function chr(c) {
        return String.fromCharCode(c);
    }).join('');
    return ret;
}
function hexStrToDec(hexStr) {
    return ~~(new Number('0x' + hexStr).toString(10));
}

function sha256(s) {
    var b2s = !(typeof s == "string")
    var md = forge.md.sha256.create();
    md.update(b2s ? bytes2string(s) : s);
    var hash = Buffer.from(md.digest().toHex().match(/.{2}/g).map(hexStrToDec));
    return hash;
}

function sha256_utf8(s) {
    var md = forge.md.sha256.create();
    md.update(s, 'utf8');
    var hash = Buffer.from(md.digest().toHex().match(/.{2}/g).map(hexStrToDec));
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
