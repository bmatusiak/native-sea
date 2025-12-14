import Gun from 'gun';
import 'gun/sea';
import SeaProxy from '../gun_webview_test/index.js';

module.exports = function _01_pair({ describe, it }) {
    describe(_01_pair.name, () => {

        it('pair generation (SeaProxy)', async ({ assert, config }) => {
            const pair = await SeaProxy.SEA.pair();
            assert.ok(pair && pair.priv && pair.pub, 'pair has priv/pub');
            assert.ok(pair && pair.epriv && pair.epub, 'pair has epriv/epub');
            config.TEST_DATA.pair = pair; // save for other tests
            config.TEST_DATA.pair_proxy = pair; // save for other tests
        });

        it('derive key, using unofficial API (NativeSea)', async ({ assert }) => {
            const SEA = Gun.SEA;
            // SEA.pair(deterministic, data, add_data) ! deterministic must be 'deterministic' string to trigger
            const pair = await SEA.pair('deterministic', 'test-seed', ['extra', 'data']);
            //{"epriv": "ujG1xpzcGdiYAKupHWuHxTtMcy68xLpWcNBgPOoMMP4", "epub": "VYgZxkA8LCgGqTT03Bff6du7NAxYil02TyXgVRQVWLc._leR7OKoNkHkyR-O6gtUN7m9M3oR-WPqCNCL_J3YQo0", "priv": "G47CXYH8GDIdPcnDk6OY1Q8WMeFfYHWgmSMTNwkIHvU", "pub": "S4oXgoB5P20ubly9xoh0z37zxA64_q1x3-9KsnB7sUw.ceTSU6uKtqCaJsNY3w0rgJoGtueqBfW5Jms2Il8uMg8"}
            assert.equal(pair.epub, 'VYgZxkA8LCgGqTT03Bff6du7NAxYil02TyXgVRQVWLc._leR7OKoNkHkyR-O6gtUN7m9M3oR-WPqCNCL_J3YQo0', 'deterministic epub matches expected');
        });

        it('pair generation & pubFromPrivate (NativeSea)', async ({ assert, config }) => {
            const TEST_PAIR = config.TEST_DATA.pair;
            const SEA = Gun.SEA;
            const pair = await SEA.pair();
            assert.ok(pair && pair.priv && pair.pub, 'pair has priv/pub');
            assert.ok(pair && pair.epriv && pair.epub, 'pair has epriv/epub');

            const epub = await SEA.pair.pubFromPrivate(TEST_PAIR.epriv);//unofficial API
            assert.equal(epub, TEST_PAIR.epub, 'epub matches expected');

            config.TEST_DATA.pair_native = pair; // save for other tests
        });

    });
};
