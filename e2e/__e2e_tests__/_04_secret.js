import NativeSea from 'native-sea';
import Gun from 'gun';
import 'gun/sea';
import SeaProxy from '../gun_webview_test/index.js';

module.exports = function _04_secret({ describe, it }) {
    describe(_04_secret.name, () => {

        let secret_sea_proxy = null;
        it('secret derivation (SeaProxy)', async ({ assert, config }) => {
            const SEA = SeaProxy.SEA;
            const TEST_PAIR_PROXY = config.TEST_DATA.pair_proxy;
            const TEST_PAIR_NATIVE = config.TEST_DATA.pair_native;

            secret_sea_proxy = await SEA.secret(TEST_PAIR_NATIVE.epub, TEST_PAIR_PROXY);
            assert.ok(typeof secret_sea_proxy === 'string', 'secret derived via SeaProxy is string');
        });

        let secret_sea_native = null;
        it('secret derivation (NativeSea)', async ({ assert, config }) => {
            NativeSea.install(Gun);
            const SEA = Gun.SEA;

            const TEST_PAIR_PROXY = config.TEST_DATA.pair_proxy;
            const TEST_PAIR_NATIVE = config.TEST_DATA.pair_native;

            secret_sea_native = await SEA.secret(TEST_PAIR_PROXY.epub, TEST_PAIR_NATIVE);
            assert.ok(typeof secret_sea_native === 'string', 'secret derived via NativeSea is string');
        });


        it('secret derivation (SeaProxy vs NativeSea)', async ({ assert }) => {

            assert.equal(secret_sea_proxy, secret_sea_native, 'SeaProxy.SEA.secret matches Gun.SEA.secret');
        });
    });
};
