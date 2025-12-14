import NativeSea from 'native-sea';
import Gun from 'gun';
import 'gun/sea';
import SeaProxy from '../gun_webview_test/index.js';

module.exports = function _06_encrypt_decrypt({ describe, it }) {
    describe(_06_encrypt_decrypt.name, () => {

        it('encrypt (SeaProxy) vs decrypt (NativeSea)', async ({ assert, config }) => {
            NativeSea.install(Gun);
            const SEA = Gun.SEA;
            const TEST_MESSAGE = config.TEST_DATA.test_message;
            const TEST_PAIR_PROXY = config.TEST_DATA.pair_proxy;
            const TEST_PAIR_NATIVE = config.TEST_DATA.pair_native;

            const secret_sea_proxy = await SeaProxy.SEA.secret(TEST_PAIR_NATIVE.epub, TEST_PAIR_PROXY);
            const secret_sea_native = await SEA.secret(TEST_PAIR_PROXY.epub, TEST_PAIR_NATIVE);


            const encrypted = await SeaProxy.SEA.encrypt(TEST_MESSAGE, secret_sea_proxy);
            const decrypted = await SEA.decrypt(encrypted, secret_sea_native);
            assert.ok(decrypted == TEST_MESSAGE, 'native decrypt returns truthy');
        });

        it('encrypt (NativeSea) vs decrypt (SeaProxy)', async ({ assert, config }) => {
            NativeSea.install(Gun);
            const SEA = Gun.SEA;
            const TEST_MESSAGE = config.TEST_DATA.test_message;
            const TEST_PAIR_PROXY = config.TEST_DATA.pair_proxy;
            const TEST_PAIR_NATIVE = config.TEST_DATA.pair_native;

            const secret_sea_proxy = await SeaProxy.SEA.secret(TEST_PAIR_NATIVE.epub, TEST_PAIR_PROXY);
            const secret_sea_native = await SEA.secret(TEST_PAIR_PROXY.epub, TEST_PAIR_NATIVE);


            const encrypted = await SEA.encrypt(TEST_MESSAGE, secret_sea_native);
            const decrypted = await SeaProxy.SEA.decrypt(encrypted, secret_sea_proxy);
            assert.ok(decrypted == TEST_MESSAGE, 'native decrypt returns truthy');
        });

    });
};
