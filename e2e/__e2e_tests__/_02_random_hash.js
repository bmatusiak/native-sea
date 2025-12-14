import NativeSea from 'native-sea';
import Gun from 'gun';
import 'gun/sea';
import SeaProxy from '../gun_webview_test/index.js';

module.exports = function _02_random_hash({ describe, it }) {
    describe(_02_random_hash.name, () => {

        let sha256_raw_proxy = null;
        let sha256_raw_native = null;
        it('random bytes and sha256 (SeaProxy)', async ({ assert, config }) => {
            const TEST_MESSAGE = config.TEST_DATA.test_message;

            const rand = await SeaProxy.SEA._getRandomBytes(16);
            assert.ok(rand, 'SeaProxy.getRandomBytes returns value');

            const h1raw = await SeaProxy.SEA._sha256_utf8(TEST_MESSAGE);
            assert.ok(h1raw, 'SeaProxy.sha256 returned');
            sha256_raw_proxy = h1raw;
        });

        it('random bytes and sha256 (NativeSea)', async ({ assert, config }) => {
            NativeSea.install(Gun);
            const SeaUtil = NativeSea.NativeModule;
            const TEST_MESSAGE = config.TEST_DATA.test_message;

            const rand = await SeaUtil.randomBytes(16);
            assert.ok(rand, 'randomBytes returns value');

            const randSync = SeaUtil.randomBytesSync && SeaUtil.randomBytesSync(16);//not normally used in api
            assert.ok(randSync, 'randomBytesSync returns value');

            const h1raw = await SeaUtil.sha256_utf8(TEST_MESSAGE);
            assert.ok(h1raw, 'sha256_utf8 returned');
            sha256_raw_native = h1raw;
        });

        function _normalizeHashToBase64(input) {
            if (!input) return input;
            if (typeof input === 'string') return input;
            try {
                if (typeof Buffer !== 'undefined') {
                    return Buffer.from(input).toString('base64');
                }
            } catch (e) { }
            try {
                const u = input instanceof Uint8Array ? input : new Uint8Array(input);
                let s = '';
                for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
                if (typeof btoa !== 'undefined') return btoa(s);
                return JSON.stringify(Array.from(u));
            } catch (e) {
                return String(input);
            }
        }

        it('sha256 check (SeaProxy vs NativeSea)', async ({ assert, config }) => {

            const h_proxy = _normalizeHashToBase64(sha256_raw_proxy);
            const h_native = _normalizeHashToBase64(sha256_raw_native);

            assert.equal(h_native, h_proxy, 'SeaProxy.sha256 equals SeaUtil.sha256 ' + 'proxy: ' + h_proxy + ' native: ' + h_native);
        });
    });
};
