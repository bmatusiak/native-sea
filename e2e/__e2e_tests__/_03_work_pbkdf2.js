import Gun from 'gun';
import 'gun/sea';
import SeaProxy from '../gun_webview_test/index.js';

module.exports = function _03_work_pbkdf2({ describe, it }) {
    describe(_03_work_pbkdf2.name, () => {
        /*
        config.TEST_DATA.work = {
            input: test_message,
            salt: 'salt',
            // PBKDF2 options (iterations, length, hash)
            opts: { iterations: 100000, length: 64 * 8, hash: { name: 'SHA-256' } }
        };
        */
        let work_proxy = null;
        let work_native = null;
        it('work (SeaProxy)', async ({ assert, config }) => {
            const SEA = SeaProxy.SEA;
            const WorkData = config.TEST_DATA.work;

            const sea_work = await SEA.work(WorkData.input, WorkData.salt, null, WorkData.opts);
            assert.ok(typeof sea_work === 'string', 'work derived via SeaProxy is string');
            work_proxy = sea_work;
        });

        it('work (NativeSea)', async ({ assert, config }) => {
            const SEA = Gun.SEA;
            const WorkData = config.TEST_DATA.work;

            const sea_work = await SEA.work(WorkData.input, WorkData.salt, null, WorkData.opts);
            assert.ok(typeof sea_work === 'string', 'work derived via NativeSea is string');
            work_native = sea_work;
        });

        it('work (SeaProxy vs NativeSea)', async ({ assert }) => {
            assert.equal(work_proxy, work_native, 'SeaProxy.SEA.work matches Gun.SEA.work');
        });
    });
};
