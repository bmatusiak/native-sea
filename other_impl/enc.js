var Crypto = require("@peculiar/webcrypto").Crypto;

var crypto = new Crypto();
var atob = require("atob");
var btoa = require("btoa");


var SEA = require("gun/sea");

var $crypto = require("crypto");


(async function () {


    var pwd = "test3";

    var EC = require('elliptic').ec;
    var ec = new EC('p256');

    var pair = {
        // pub: 'AvMHwJaxJZ4g5TgUr8WmGBBebsHBsMqYz5Ek9cBk8c4.N03mno2-gJKYZ7IFAjcDD06TtT_wKIDzeeioeeodCvw',
        // priv: 'c_IT_l3LBgMy-jcksu8ZxseS99HBSFWIcnvEE574Oe4',
        epub: '4uR2v4b_t4qXTbKhE-ucgYKInBblsv7rodXQmx6V5R0.v3DMdf6QKNXSeUXHbP5956nwFKiTdfnP4Ivvi7bjRDY',
        epriv: 'IyoH-X2D5Zvf5G2Mnlz6CmIkN428_4FiBLmZwp-lwPI'
    }


    var privateKeyA = $crypto.createHash('sha256').update(pwd).digest().toString("hex");
    var publicKeyA = ec.keyFromPrivate(privateKeyA, "hex").getPublic("hex");


    console.log(publicKeyA.length, publicKeyA.toString("base64"));
    console.log(Uint8Array.from(publicKeyA));


    console.log("---");
    var alice_pair = {};
    ONLYKEY_ECDH_P256_to_EPUB(Buffer.from(publicKeyA, "hex"), async function (seaPub) {
        alice_pair.epub = seaPub;
        alice_pair.epriv = arrayBufToBase64UrlEncode(Buffer.from(privateKeyA, "hex"));
        var secret = await SEA.secret(pair.epub, alice_pair)
        console.log("SEA_pair", pair);
        console.log("ECC_alice_pair", alice_pair);
        console.log("SEA_secret", secret);


        // var shared2 = key2.derive(key1.getPublic());

        var secre2 = await SEA.secret(alice_pair.epub, pair)

        console.log("SEA_secret2", secre2);

        var ec_Alice = ec.keyFromPrivate(privateKeyA, "hex");
        EPUB_TO_ONLYKEY_ECDH_P256(pair.epub, function (pair_epub_raw) {
            var ec_sea = ec.keyFromPublic(Buffer.from(pair_epub_raw).toString("hex"), "hex")
            var EC_secret3 = ec_Alice.derive(ec_sea.getPublic());
            console.log("EC_secret3", arrayBufToBase64UrlEncode(Buffer.from(EC_secret3.toString("hex"), "hex")));


        });
        // EPUB_TO_ONLYKEY_ECDH_P256(pair.epub, function(pair_epub_raw) {
        //   console.log("pair_epub_raw", pair_epub_raw)
        //     eccrypto.derive(privateKeyA,  Buffer.from(pair_epub_raw)).then(function(sharedKey1) {
        //         console.log("ECC_secret", secret);
        //     });

        // });
    });


})();

function u2f_unb64(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/');
    return atob(s + '==='.slice((s.length + 3) % 4));
}

function arrayBufToBase64UrlEncode(buf) {
    var binary = '';
    var bytes = new Uint8Array(buf);
    for (var i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary)
        .replace(/\//g, '_')
        .replace(/=/g, '')
        .replace(/\+/g, '-');
}

function arrayBufToBase64UrlDecode(ba64) {
    var binary = u2f_unb64(ba64);
    var bytes = [];
    for (var i = 0; i < binary.length; i++) {
        bytes.push(binary.charCodeAt(i));
    }

    return new Uint8Array(bytes);
}

function EPUB_TO_ONLYKEY_ECDH_P256(ePub, callback) {
    var xdecoded = arrayBufToBase64UrlDecode(ePub.split(".")[0]);
    var ydecoded = arrayBufToBase64UrlDecode(ePub.split(".")[1]);

    var publicKeyRawBuffer = Uint8Array.from([4].concat(Array.from(xdecoded)).concat(Array.from(ydecoded)));

    if (callback)
        callback(publicKeyRawBuffer);

    return publicKeyRawBuffer;
    /*
    var publicKeyRawBuffer = new Uint8Array(65);
    var h = -1;
    for (var i in xdecoded) {
        h++;
        publicKeyRawBuffer[h] = xdecoded[i];
    }
    for (var j in ydecoded) {
        h++;
        publicKeyRawBuffer[h] = ydecoded[j];
    }
    if (publicKeyRawBuffer[0] == 0) {
        publicKeyRawBuffer = Array.from(publicKeyRawBuffer)
        publicKeyRawBuffer.unshift()
        publicKeyRawBuffer = Uint8Array.from(publicKeyRawBuffer);
    }
    console.log("epub to raw", ePub, publicKeyRawBuffer)
    if (callback)
        callback(publicKeyRawBuffer)
    return publicKeyRawBuffer;
    */
}

async function ONLYKEY_ECDH_P256_to_EPUB(publicKeyRawBuffer, callback) {
    //https://stackoverflow.com/questions/56846930/how-to-convert-raw-representations-of-ecdh-key-pair-into-a-json-web-key

    //
    var orig_publicKeyRawBuffer = Uint8Array.from(publicKeyRawBuffer);

    //console.log("publicKeyRawBuffer  B", publicKeyRawBuffer)
    // publicKeyRawBuffer = Array.from(publicKeyRawBuffer)
    // publicKeyRawBuffer.unshift(publicKeyRawBuffer.pop());
    // publicKeyRawBuffer = Uint8Array.from(publicKeyRawBuffer)

    //console.log("publicKeyRawBuffer  F", publicKeyRawBuffer)

    if (false) {
        var $importedPubKey = await crypto.subtle.importKey(
            'raw', orig_publicKeyRawBuffer, {
            name: 'ECDH',
            namedCurve: 'P-256'
        },
            true, []
        ).catch(function (err) {
            console.error(err);
        }).then(function (importedPubKey) {
            exportKey(importedPubKey)
        });
    }
    else {
        var x = publicKeyRawBuffer.slice(1, 33);
        var y = publicKeyRawBuffer.slice(33, 66);

        crypto.subtle.importKey(
            'jwk', {
            kty: "EC",
            crv: "P-256",
            x: arrayBufToBase64UrlEncode(x),
            y: arrayBufToBase64UrlEncode(y)
        }, {
            name: 'ECDH',
            namedCurve: 'P-256'
        },
            true, []
        ).catch(function (err) {
            console.error(err);
        }).then(function (importedPubKey) {
            if (importedPubKey)
                exportKey(importedPubKey)
        });
    }

    function exportKey(importedPubKey) {

        crypto.subtle.exportKey(
            "jwk", //can be "jwk" (public or private), "raw" (public only), "spki" (public only), or "pkcs8" (private only)
            importedPubKey //can be a publicKey or privateKey, as long as extractable was true
        )
            .then(function (keydata) {

                var OK_SEA_epub = keydata.x + '.' + keydata.y;

                // console.log("raw to epub", OK_SEA_epub, orig_publicKeyRawBuffer)

                if (callback)
                    callback(OK_SEA_epub);

            })
            .catch(function (err) {
                console.error(err);
            });

    }

}