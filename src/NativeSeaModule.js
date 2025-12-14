import { requireNativeModule } from 'expo';

const NativeModule = requireNativeModule('NativeSea');
// Bridge to the native implementation (C++/platform) exposed as the
// `NativeSea` native module. Methods here should match native exports.
function toIntArray(x) {
    if (!x && x !== 0) return x;
    if (x instanceof Uint8Array) return Array.from(x);
    if (Array.isArray(x)) return x;
    // Node Buffer
    if (x && x.constructor && x.constructor.name === 'Buffer') return Array.from(x);
    // If it's an ArrayBuffer
    if (x instanceof ArrayBuffer) return Array.from(new Uint8Array(x));
    // If it's an ArrayBuffer view-like (TypedArray/DataView)
    if (x && x.buffer && x.byteLength !== undefined) return Array.from(new Uint8Array(x.buffer, x.byteOffset, x.byteLength));
    return x;
}

const Buffer = (() => require("buffer").Buffer)();
const { TextEncoder, TextDecoder } = (() => require("text-encoding"))();
(function () {
    window = global || window;
    global.Buffer = global.Buffer || Buffer;
    global.TextEncoder = TextEncoder;
    global.TextDecoder = TextDecoder;
    window.crypto = window.crypto || {};
    window.localStorage = {};
    window.localStorage.getItem = function (key) {
        return window.localStorage[key] || null;
    };
    window.localStorage.setItem = function (key, value) {
        window.localStorage[key] = value;
    };
    window.localStorage.removeItem = function (key) {
        delete window.localStorage[key];
    };
    window.crypto.getRandomValues = function getRandomValues(typedArray) {
        var Type;
        if (typedArray instanceof Int8Array) { Type = Int8Array }
        if (typedArray instanceof Uint8Array) { Type = Uint8Array }
        if (typedArray instanceof Uint8ClampedArray) { Type = Uint8ClampedArray }
        if (typedArray instanceof Int16Array) { Type = Int16Array }
        if (typedArray instanceof Uint16Array) { Type = Uint16Array }
        if (typedArray instanceof Int32Array) { Type = Int32Array }
        if (typedArray instanceof Uint32Array) { Type = Uint32Array }
        if (typedArray instanceof BigInt64Array) { Type = BigInt64Array }
        if (typedArray instanceof BigUint64Array) { Type = BigUint64Array }
        var rnd = new Type(Int8Array.from(SeaUtil.randomBytesSync(typedArray.length)));
        for (let i = 0; i < typedArray.length; i++) {
            typedArray[i] = rnd[i];
        }
        return rnd;
    }
})();
const elliptic = require("elliptic");//pair/secret/sign/verify
const EC = elliptic.ec;

// helper: decode various native randomBytes return types to Uint8Array
async function getRandomValues(len) {
    try {
        if (NativeModule.randomBytesSync) {
            const r = NativeModule.randomBytesSync(len);
            return (r instanceof Uint8Array) ? r : Uint8Array.from(r);
        }
        const res = await SeaUtil.randomBytes(len);
        if (!res) return new Uint8Array(len);
        if (typeof res === 'string') {
            const b = Buffer.from(res, 'base64');
            return Uint8Array.from(b);
        }
        if (Array.isArray(res)) return Uint8Array.from(res);
        if (res instanceof Uint8Array) return res;
        if (res.buffer) return Uint8Array.from(res);
    } catch (e) { }
    return new Uint8Array(len);
}

function arrayBufToBase64UrlEncode(buf) {
    var binary = '';
    var bytes = new Uint8Array(buf);
    for (var i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return Buffer.from(binary, 'binary').toString('base64').replace(/\//g, '_').replace(/=/g, '').replace(/\+/g, '-');
}
function u8(a) { return Uint8Array.from(a); }
function bytes2string(bytes) {
    return Array.from(bytes).map(function chr(c) { return String.fromCharCode(c); }).join('');
}

async function hash256_utf8(s) {
    try {
        const r = await SeaUtil.sha256_utf8(s);
        if (typeof r === 'string') {
            // assume hex
            return Uint8Array.from(Buffer.from(r, 'hex'));
        }
        if (r instanceof Uint8Array) return r;
        if (Array.isArray(r)) return Uint8Array.from(r);
        if (r && r.buffer) return Uint8Array.from(r);
        return Uint8Array.from(Buffer.from(String(r), 'base64'));
    } catch (e) {
        return Uint8Array.from([]);
    }
}

// expose hashing helpers on shim so installers can access them outside setup scope
// (ensure `shim` exists first — it is created below)

async function hash256(d) {
    var t = (typeof d == 'string') ? d : await shim.stringify(d);
    return await hash256_utf8(t);
}

const shim = { Buffer }
// attach helper functions
shim.hash256_utf8 = hash256_utf8;
shim.u8 = u8;
shim.bytes2string = bytes2string;
// shim.crypto = window.crypto || window.msCrypto
// shim.subtle = (shim.crypto || o).subtle || (shim.crypto || o).webkitSubtle;
shim.TextEncoder = TextEncoder;
shim.TextDecoder = TextDecoder;
shim.random = async (len) => shim.Buffer.from(await getRandomValues(len));
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
    } catch (e) { null; }
    return t;
}

const SeaUtil = {
    pair: () => NativeModule.pair(),
    publicFromPrivate: (priv) => NativeModule.publicFromPrivate(priv),
    secret: (pub, epriv) => NativeModule.secret(pub, epriv),
    sign: (priv, data) => NativeModule.sign(priv, toIntArray(data)),
    verify: async (pub, data, sig) => {
        // Normalize: if a single-part key is provided (no dot) it may be a private key
        // so try to derive a public form via native publicFromPrivate(). If that fails
        // fall back to passing the original value through.
        try {
            if (typeof pub === 'string' && pub.indexOf('.') === -1) {
                const maybe = await NativeModule.publicFromPrivate(pub);
                if (maybe && maybe.indexOf('.') !== -1) pub = maybe;
            }
        } catch (e) { /* ignore and use original pub */ }
        return NativeModule.verify(pub, toIntArray(data), sig);
    },
    encrypt: (msg, pKey, iv) => {
        // minimal shim: forward to native implementation
        return NativeModule.encrypt(msg, pKey, iv)
    },
    decrypt: (ct, pKey, iv, tag) => {
        return NativeModule.decrypt(ct, pKey, iv, tag)
    },
    sha256_utf8: (s) => NativeModule.sha256_utf8 ? NativeModule.sha256_utf8(s) : NativeModule.sha256(s),
    sha256bytes: (b64) => (NativeModule.sha256bytes ? NativeModule.sha256bytes(b64) : NativeModule.sha256bytes_base64 ? NativeModule.sha256bytes_base64(b64) : null),
    randomBytes: async (len) => toIntArray(await NativeModule.randomBytes(len)),
    randomBytesSync: (len) => {
        const r = (NativeModule.randomBytesSync ? NativeModule.randomBytesSync(len) : null);
        return toIntArray(r);
    },
    pbkdf2: (data, salt, iter, ks) => {
        // If salt is not a string, normalize it.
        if (typeof salt !== 'string') {
            const arr = toIntArray(salt);
            // Prefer the List<Int> native overload for array-like salts.
            if (Array.isArray(arr) || (arr && arr.constructor && arr.constructor.name === 'Uint8Array')) {
                return NativeModule.pbkdf2_2(data, Array.from(arr), iter, ks);
            }
            return NativeModule.pbkdf2_2(data, arr, iter, ks);
        }
        return NativeModule.pbkdf2(data, salt, iter, ks);
    },
}

const NativeSeaModule = {
    NativeModule,
    setupGun: function (Gun) {


        this.shim = shim;
    },
    install: function (Gun) {
        if (Gun.RN) return; // already installed
        this.setupGun(Gun);
        this.Gun = Gun;
        this.installPair();
        this.installWork();
        this.installSecret();
        this.installVerify();
        this.installSign();
        this.installEncrypt();
        this.installDecrypt();
        Gun.RN = true;
    },
    installPair: function () {
        const Gun = this.Gun;
        const NativeModule = this.NativeModule;
        const SEA = Gun.SEA;

        function hash_key(data, additional_data) {
            var ec = new EC('p256');
            var h = ec.hash().update(data)
            if (additional_data) {
                if (!(additional_data instanceof Array)) additional_data = [additional_data];
                for (let i = 0; i < additional_data.length; i++) {
                    if (!additional_data[i]) continue;
                    h.update(additional_data[i]);
                }
            }
            return h.digest();
        }

        async function genKeyPair(private_key, additional_data) {
            if (additional_data && !(additional_data instanceof Array))
                additional_data = [additional_data];
            if (private_key) {
                var priv = arrayBufToBase64UrlEncode(hash_key(private_key, additional_data));
                var pub = await SeaUtil.publicFromPrivate(priv);
                return { pub, priv }
            }
            else {
                return await SeaUtil.pair();
            }
        }

        async function doPair(deterministic, data, add_data) {
            var pair;
            if (deterministic == "deterministic") {
                pair = await (async () => {
                    var { pub, priv } = await genKeyPair(data, ["s"].concat(add_data));
                    var { pub: epub, priv: epriv } = await genKeyPair(data, ["d"].concat(add_data));
                    return { pub, priv, epub, epriv };
                })();
            } else {
                pair = await (async () => {
                    var { pub, priv } = await genKeyPair();
                    var { pub: epub, priv: epriv } = await genKeyPair();
                    return { pub, priv, epub, epriv };
                })();
                if (typeof deterministic == "function") deterministic(pair);//callback is only for random
            }
            return pair;
        }
        SEA.pair = doPair;
        // Provide the legacy nested API: SEA.pair.pubFromPrivate
        SEA.pair.pubFromPrivate = function (priv) { return SeaUtil.publicFromPrivate(priv); };
    },
    installWork: function () {
        const Gun = this.Gun;
        const SEA = Gun.SEA;

        async function doWork(data, pair, cb, opt) {
            var u;
            var salt = (pair || {}).epub || pair;
            opt = opt || {};
            if (salt instanceof Function) {
                cb = salt;
                salt = u;
            }
            data = (typeof data == 'string') ? data : await shim.stringify(data);
            if ('sha' === (opt.name || '').toLowerCase().slice(0, 3)) {
                var rsha = shim.Buffer.from(await hash256(data), 'binary').toString(opt.encode || 'base64')
                if (cb) try { cb(rsha) } catch (e) { }
                return rsha;
            }
            salt = salt || (await shim.random(9));
            var S = { pbkdf2: { hash: { name: 'SHA-256' }, iter: 100000, ks: 64 } };
            var r = await SeaUtil.pbkdf2(data, salt, S.pbkdf2.iter, S.pbkdf2.ks * 8);
            data = (await shim.random(data.length))
            if (cb) { try { cb(null, r) } catch (e) { } }
            return r;
        }

        SEA.work = doWork;
    },
    installSecret: function () {
        const Gun = this.Gun;
        const SEA = Gun.SEA;

        async function doDerive(key, pair, cb, opt) {
            opt = opt || {};
            if (!pair || !pair.epriv || !pair.epub) {
                if (!SEA.I) throw new Error('No identity');
                pair = await SEA.I(null, { what: key, how: 'secret', why: opt.why });
            }
            var pub = key.epub || key;
            var epriv = pair.epriv || pair;
            var r = await SeaUtil.secret(pub, epriv);
            if (cb) { try { cb(null, r) } catch (e) { } }
            return r;
        }

        SEA.secret = doDerive;
    },
    installVerify: function () {
        const Gun = this.Gun;
        const SEA = Gun.SEA;

        async function doVerify(data, pair, cb, opt) {
            var u;
            var json = await shim.S.parse(data);
            if (false === pair) {
                var raw = await shim.S.parse(json.m);
                if (cb) try { cb(null, raw) } catch (e) { }
                return raw;
            }
            opt = opt || {};
            opt.ok = "?";
            var pub = pair.pub || pair;
            var json_dd = await hash256(json.m);
            var check = await SeaUtil.verify(pub, json_dd, json.s);
            if (!check) { throw "Signature did not match." }
            var r = check ? await shim.S.parse(json.m) : u;
            if (cb) { try { cb(null, r) } catch (e) { } }
            return r;
        }

        SEA.verify = doVerify;
    },
    installSign: function () {
        const Gun = this.Gun;
        const SEA = Gun.SEA;

        async function doSign(data, pair, cb, opt) {
            var u;
            opt = opt || {};
            if (!(pair || opt).priv) {
                if (!SEA.I) throw new Error('No identity');
                pair = await SEA.I(null, { what: data, how: 'sign', why: opt.why });
            }
            if (u === data) { throw '`undefined` not allowed.' }
            var json = await shim.S.parse(data);
            var check = opt.check = opt.check || json;
            if (SEA.verify && (SEA.opt && SEA.opt.check ? SEA.opt.check(check) : (check && check.s && check.m))
                && u !== await SEA.verify(check, pair)) {
                var r = await shim.S.parse(check);
                if (!opt.raw) r = r;
                if (cb) try { cb(null, r) } catch (e) { }
                return r;
            }
            var priv = pair.priv;
            var json_dd = await hash256(json);
            var siged = await SeaUtil.sign(priv, json_dd);
            var sig = { m: json, s: siged };
            if (!opt.raw) { sig = 'SEA' + await shim.stringify(sig) }
            if (cb) { try { cb(null, sig) } catch (e) { } }
            return sig;
        }

        SEA.sign = doSign;
    },
    installEncrypt: function () {
        const Gun = this.Gun;
        const SEA = Gun.SEA;

        async function doEncrypt(data, pair, cb, opt) {
            var u;
            opt = opt || {};
            var key = (pair || opt).epriv || pair;
            if (u === data) { throw '`undefined` not allowed.' }
            if (!key) {
                if (!SEA.I) throw new Error('No identity');
                pair = await SEA.I(null, { what: data, how: 'encrypt', why: opt.why });
                key = pair.epriv || pair;
            }
            var msg = (typeof data == 'string') ? data : await shim.stringify(data);
            // Use 12-byte IV for AES-GCM to match typical nonce length and native expectation
            var iv = Buffer.from(await shim.random(12)).toString("base64");
            var salt = Buffer.from(await shim.random(9));
            var tkey = key + shim.bytes2string(salt);
            var pKey = Array.from(await shim.hash256_utf8(tkey));
            msg = Buffer.from(msg).toString("base64");
            pKey = Buffer.from(pKey).toString("base64");
            var ct = await SeaUtil.encrypt(msg, pKey, iv);
            var r = {
                ct,
                s: salt.toString("base64"),
                iv: iv
            }
            if (!opt.raw) { r = 'SEA' + await shim.stringify(r) }
            if (cb) { try { cb(null, r) } catch (e) { } }
            return r;
        }

        SEA.encrypt = doEncrypt;
    },
    installDecrypt: function () {
        const Gun = this.Gun;
        const SEA = Gun.SEA;

        async function doDecrypt(data, pair, cb, opt) {
            opt = opt || {};
            var key = (pair || opt).epriv || pair;
            if (!key) {
                if (!SEA.I) throw new Error('No identity');
                pair = await SEA.I(null, { what: data, how: 'decrypt', why: opt.why });
                key = pair.epriv || pair;
            }
            var json = await shim.S.parse(data);
            var tkey = key + shim.bytes2string(Buffer.from(json.s, "base64"))
            var pKey = Array.from(await shim.hash256_utf8(tkey));
            var ctx = shim.u8(Buffer.from(json.ct, "base64"));
            var tag = ctx.slice(ctx.length - 16, ctx.length);
            var ct = ctx.slice(0, ctx.length - 16);
            var r = await SeaUtil.decrypt(
                Buffer.from(ct).toString("base64"),
                Buffer.from(pKey).toString("base64"),
                json.iv,
                Buffer.from(tag).toString("base64"),
            )
            r = await shim.S.parse(r);

            if (cb) { try { cb(null, r) } catch (e) { } }
            return r;
        }

        SEA.decrypt = doDecrypt;
    }
}

export default NativeSeaModule;