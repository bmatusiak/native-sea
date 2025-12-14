import NativeSea from 'native-sea';
import Gun from 'gun';
import 'gun/sea';
import SeaProxy from '../gun_webview_test/index.js';
import GunHost from '../gun_webview_test/host.js';
NativeSea.install(Gun);

module.exports = function _00_gun_setup({ describe, it }) {
    describe(_00_gun_setup.name, () => {
        it('SeaProxy setup', async ({ log, assert, render }) => {
            const { WebViewComponent, gunView } = await GunHost(SeaProxy.contextSrc, SeaProxy.debug);

            render(WebViewComponent);

            await new Promise((resolve, reject) => {
                const to = setTimeout(() => reject(new Error('gunView ready timeout (10s)')), 10000);
                gunView.on('ready', () => {
                    clearTimeout(to);
                    resolve();
                });
            });
            SeaProxy.setContext(gunView);

        });

        it('NativeSea setup', async ({ log, assert }) => {
            assert.ok(typeof Gun !== 'undefined', 'Gun is defined');
            assert.ok(typeof Gun.SEA !== 'undefined', 'Gun.SEA is defined');
            assert.ok(typeof Gun.RN !== 'undefined', 'Gun.RN is defined');
        });

        //generate test data to use for testing
        it('Generate test data', async ({ log, config }) => {
            config.TEST_DATA = {};

            // generate test message
            config.TEST_DATA.test_message = 'Test message data for testing at ' + new Date().toISOString();

            // work / pbkdf2
            config.TEST_DATA.work = {
                input: config.TEST_DATA.test_message,
                salt: 'salt',
                // PBKDF2 options (iterations, length, hash)
                opts: { iterations: 100000, length: 64 * 8, hash: { name: 'SHA-256' } }
            };

        });

    });
};
