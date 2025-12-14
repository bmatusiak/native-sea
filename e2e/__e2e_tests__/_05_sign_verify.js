import NativeSea from 'native-sea';
import Gun from 'gun';
import 'gun/sea';
import SeaProxy from '../gun_webview_test/index.js';

module.exports = function _05_sign_verify({ describe, it }) {
    describe(_05_sign_verify.name, () => {

        it('sign (SeaProxy) vs verify (NativeSea)', async ({ assert, config }) => {
            NativeSea.install(Gun);
            const SEA = Gun.SEA;
            const TEST_MESSAGE = config.TEST_DATA.test_message;
            const TEST_PAIR_PROXY = config.TEST_DATA.pair_proxy;


            const sig = await SeaProxy.SEA.sign(TEST_MESSAGE, TEST_PAIR_PROXY);
            const verify = await SEA.verify(sig, TEST_PAIR_PROXY.pub);
            assert.ok(verify, 'native verify returns truthy');
        });

        it('sign (NativeSea) vs verify (SeaProxy)', async ({ assert, config }) => {
            NativeSea.install(Gun);
            const SEA = Gun.SEA;
            const TEST_MESSAGE = config.TEST_DATA.test_message;
            const TEST_PAIR_NATIVE = config.TEST_DATA.pair_native;


            const sig = await SEA.sign(TEST_MESSAGE, TEST_PAIR_NATIVE);
            const verify = await SeaProxy.SEA.verify(sig, TEST_PAIR_NATIVE.pub);
            assert.ok(verify, 'proxy verify returns truthy');

        });



    });
};
