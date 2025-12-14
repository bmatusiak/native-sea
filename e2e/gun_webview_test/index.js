
const out = {};
// configurable RPC timeout (ms)
out.rpcTimeout = 10000;

function genId(prefix) {
    try {
        if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
            const arr = new Uint8Array(6);
            crypto.getRandomValues(arr);
            const hex = Array.from(arr).map(b => b.toString(16).padStart(2, '0')).join('');
            return `${prefix}-${Date.now()}-${hex}`;
        }
    } catch (e) { }
    return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}
out.contextSrc = `
    // _getRandomBytes
    // _sha256_utf8
    // SEA.work(data, pair, callback, opt)
    // SEA.pair(cb, opt)
    // SEA.sign(data, pair)
    // SEA.verify(message, pair.pub)
    // SEA.secret(other.epub, pair)
    // SEA.encrypt(data, pair)
    // SEA.decrypt(message, pair)

    webview.on('_getRandomBytes', async(args) => {
        //using window.crypto webcrypto API to get random bytes
        let bytes;
        try {
            if (window.crypto && window.crypto.getRandomValues) {
                const arr = new Uint8Array(args.length);
                window.crypto.getRandomValues(arr);
                // send as plain array so JSON.stringify/postMessage works across the bridge
                bytes = Array.from(arr);
            } else {
                throw new Error('No crypto.getRandomValues available');
            }
        } catch (e) {
            webview.emit('_getRandomBytes-result-' + args.id, null);
            return;
        }
        webview.emit('_getRandomBytes-result-' + args.id, bytes);
    });

    webview.on('_sha256_utf8', async(args) => {
        //using window.crypto webcrypto API to compute sha256
        let hash;
        try {
            if (window.crypto && window.crypto.subtle && window.TextEncoder) {
                const encoder = new TextEncoder();
                const data = encoder.encode(args.data);
                const digest = await window.crypto.subtle.digest('SHA-256', data);
                const hashArray = Array.from(new Uint8Array(digest));
                hash = hashArray;
            } else {
                throw new Error('No crypto.subtle.digest available');
            }
        } catch (e) {
            webview.emit('_sha256_utf8-result-' + args.id, null);
            return;
        }
        webview.emit('_sha256_utf8-result-' + args.id, hash);
    });

    webview.on('work', async(args) => {
        Gun.SEA.work(args.data, args.pair, (res) => {
            webview.emit('work-result-' + args.id, res);
        }, args.opt);
    });

    webview.on('pair', async(args) => {
        Gun.SEA.pair((res) => {
            webview.emit('pair-result-' + args.id, res);
        }, args.opt);  
    });

    webview.on('sign', async(args) => {
        Gun.SEA.sign(args.data, args.pair, (res) => {
            webview.emit('sign-result-' + args.id, res);
        });
    });

    webview.on('verify', async(args) => {
        Gun.SEA.verify(args.message, args.pub, (res) => {
            webview.emit('verify-result-' + args.id, res);
        });
    });
    
    webview.on('secret', async(args) => {
        Gun.SEA.secret(args.otherEpub, args.pair, (res) => {
            webview.emit('secret-result-' + args.id, res);
        }); 
    });

    webview.on('encrypt', async(args) => {
        Gun.SEA.encrypt(args.data, args.pair, (res) => {
            webview.emit('encrypt-result-' + args.id, res);
        });
    });

    webview.on('decrypt', async(args) => {
        Gun.SEA.decrypt(args.message, args.pair, (res) => {
            webview.emit('decrypt-result-' + args.id, res);
        });
    });
        
    
`;

out.setContext = function (ctx) {
    globalThis.__view_context = ctx;
};

// SEA.work(data, pair, callback, opt)
// SEA.pair(cb, opt)
// SEA.sign(data, pair)
// SEA.verify(message, pair.pub)
// SEA.secret(other.epub, pair)
// SEA.encrypt(data, pair)
// SEA.decrypt(message, pair)
out.SEA = {
    _getRandomBytes: function (length) {//not part of SEA API, used internally
        if (!globalThis.__view_context) {
            throw new Error('No webview context set for getRandomBytes');
        }
        return new Promise(async (resolve, reject) => {
            const id = genId('_getRandomBytes');
            globalThis.__view_context.emit('_getRandomBytes', { id, length });
            const to = setTimeout(() => {
                try { globalThis.__view_context.removeAllListeners('_getRandomBytes-result-' + id); } catch (_) { }
                reject(new Error('_getRandomBytes timeout (' + out.rpcTimeout + 'ms)'));
            }, out.rpcTimeout);
            globalThis.__view_context.once('_getRandomBytes-result-' + id, (res) => {
                clearTimeout(to);
                if (!res || !(res instanceof Uint8Array || Array.isArray(res))) return reject(new Error('Invalid _getRandomBytes result'));
                // Normalize to Uint8Array for callers
                try {
                    if (Array.isArray(res)) return resolve(Uint8Array.from(res));
                    return resolve(res);
                } catch (e) {
                    return reject(new Error('Failed to normalize _getRandomBytes result'));
                }
            });
        });
    },
    _sha256_utf8: async function (data) {//not part of SEA API, used internally
        if (!globalThis.__view_context) {
            throw new Error('No webview context set for _sha256_utf8');
        }
        return new Promise(async (resolve, reject) => {
            const id = genId('_sha256_utf8');
            globalThis.__view_context.emit('_sha256_utf8', { id, data });
            const to = setTimeout(() => {
                try { globalThis.__view_context.removeAllListeners('_sha256_utf8-result-' + id); } catch (_) { }
                reject(new Error('_sha256_utf8 timeout (' + out.rpcTimeout + 'ms)'));
            }, out.rpcTimeout);
            globalThis.__view_context.once('_sha256_utf8-result-' + id, (res) => {
                clearTimeout(to);
                if (!res || !(res instanceof Uint8Array || Array.isArray(res))) return reject(new Error('Invalid _sha256_utf8 result'));
                // Normalize to Uint8Array for callers
                try {
                    if (Array.isArray(res)) return resolve(Uint8Array.from(res));
                    return resolve(res);
                } catch (e) {
                    return reject(new Error('Failed to normalize _sha256_utf8 result'));
                }
            });
        });
    },
    work: function (data, pair, callback, opt) {
        if (!globalThis.__view_context) {
            throw new Error('No webview context set for SEA.work');
        }
        return new Promise(async (resolve, reject) => {
            const id = genId('work');
            globalThis.__view_context.emit('work', { id, data, pair, opt });
            const to = setTimeout(() => {
                try { globalThis.__view_context.removeAllListeners('work-result-' + id); } catch (_) { }
                reject(new Error('SEA.work timeout (' + out.rpcTimeout + 'ms)'));
            }, out.rpcTimeout);
            globalThis.__view_context.once('work-result-' + id, (res) => {
                clearTimeout(to);
                if (!res || typeof res !== 'string') return reject(new Error('Invalid SEA.work result'));
                resolve(res);
            });
        });
    },
    pair: function (cb, opt) {
        if (!globalThis.__view_context) {
            throw new Error('No webview context set for SEA.pair');
        }
        return new Promise(async (resolve, reject) => {
            const id = genId('pair');
            globalThis.__view_context.emit('pair', { id, opt });
            const to = setTimeout(() => {
                try { globalThis.__view_context.removeAllListeners('pair-result-' + id); } catch (_) { }
                reject(new Error('SEA.pair timeout (' + out.rpcTimeout + 'ms)'));
            }, out.rpcTimeout);
            globalThis.__view_context.once('pair-result-' + id, (res) => {
                clearTimeout(to);
                if (!res || typeof res.pub !== 'string' || typeof res.priv !== 'string') return reject(new Error('Invalid SEA.pair result'));
                resolve(res);
            });
        });
    },
    sign: function (data, pair) {
        if (!globalThis.__view_context) {
            throw new Error('No webview context set for SEA.sign');
        }
        return new Promise(async (resolve, reject) => {
            const id = genId('sign');
            globalThis.__view_context.emit('sign', { id, data, pair });
            const to = setTimeout(() => {
                try { globalThis.__view_context.removeAllListeners('sign-result-' + id); } catch (_) { }
                reject(new Error('SEA.sign timeout (' + out.rpcTimeout + 'ms)'));
            }, out.rpcTimeout);
            globalThis.__view_context.once('sign-result-' + id, (res) => {
                clearTimeout(to);
                if (!res) return reject(new Error('Invalid SEA.sign result'));
                resolve(res);
            });
        });
    },
    verify: function (message, pub) {
        if (!globalThis.__view_context) {
            throw new Error('No webview context set for SEA.verify');
        }
        return new Promise(async (resolve, reject) => {
            const id = genId('verify');
            globalThis.__view_context.emit('verify', { id, message, pub });
            const to = setTimeout(() => {
                try { globalThis.__view_context.removeAllListeners('verify-result-' + id); } catch (_) { }
                reject(new Error('SEA.verify timeout (' + out.rpcTimeout + 'ms)'));
            }, out.rpcTimeout);
            globalThis.__view_context.once('verify-result-' + id, (res) => {
                clearTimeout(to);
                if (res === undefined || res === null) return reject(new Error('Invalid SEA.verify result'));
                resolve(res);
            });
        });
    },
    secret: function (otherEpub, pair) {
        if (!globalThis.__view_context) {
            throw new Error('No webview context set for SEA.secret');
        }
        return new Promise(async (resolve, reject) => {
            const id = genId('secret');
            globalThis.__view_context.emit('secret', { id, otherEpub, pair });
            const to = setTimeout(() => {
                try { globalThis.__view_context.removeAllListeners('secret-result-' + id); } catch (_) { }
                reject(new Error('SEA.secret timeout (' + out.rpcTimeout + 'ms)'));
            }, out.rpcTimeout);
            globalThis.__view_context.once('secret-result-' + id, (res) => {
                clearTimeout(to);
                if (!res) return reject(new Error('Invalid SEA.secret result'));
                resolve(res);
            });
        });
    },
    encrypt: function (data, pair) {
        if (!globalThis.__view_context) {
            throw new Error('No webview context set for SEA.encrypt');
        }
        return new Promise(async (resolve, reject) => {
            const id = genId('encrypt');
            globalThis.__view_context.emit('encrypt', { id, data, pair });
            const to = setTimeout(() => {
                try { globalThis.__view_context.removeAllListeners('encrypt-result-' + id); } catch (_) { }
                reject(new Error('SEA.encrypt timeout (' + out.rpcTimeout + 'ms)'));
            }, out.rpcTimeout);
            globalThis.__view_context.once('encrypt-result-' + id, (res) => {
                clearTimeout(to);
                if (!res || typeof res !== 'string') return reject(new Error('Invalid SEA.encrypt result'));
                resolve(res);
            });
        });
    },
    decrypt: function (message, pair) {
        if (!globalThis.__view_context) {
            throw new Error('No webview context set for SEA.decrypt');
        }
        return new Promise(async (resolve, reject) => {
            const id = genId('decrypt');
            globalThis.__view_context.emit('decrypt', { id, message, pair });
            const to = setTimeout(() => {
                try { globalThis.__view_context.removeAllListeners('decrypt-result-' + id); } catch (_) { }
                reject(new Error('SEA.decrypt timeout (' + out.rpcTimeout + 'ms)'));
            }, out.rpcTimeout);
            globalThis.__view_context.once('decrypt-result-' + id, (res) => {
                clearTimeout(to);
                if (res === undefined || res === null) return reject(new Error('Invalid SEA.decrypt result'));
                resolve(res);
            });
        });
    }
};

export default out;
