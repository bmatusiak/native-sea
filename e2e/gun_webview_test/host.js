import React from 'react';
import { WebView } from 'react-native-webview';
import { EventEmitter } from 'events';

export default async function Host(webviewWorkerSrc, showIO = false) {
    function fetchBundle(name, options = {
        platform: 'android',
        dev: 'false',
        minify: 'false',
        hot: 'false'
    }) {
        let opts = '';
        if (options) {
            const params = [];
            for (const k in options) {
                params.push(`${encodeURIComponent(k)}=${encodeURIComponent(options[k])}`);
            }
            if (params.length > 0) {
                opts = `?${params.join('&')}`;
            }
        }
        const url = `http://localhost:8081/${name}.bundle${opts}`;
        console.log('[WEBVIEW]', 'webview fetch url:', url);
        return fetch(url);
    }
    const viewSrc_JS = await (await fetchBundle('gun_webview_test/worker')).text();
    const html = `<html><body><script language='javascript'>
    window._start = function(webview) {
        window.webview = webview;
        ${webviewWorkerSrc}
    };
    </script>
    <script language='javascript'>
    ${viewSrc_JS}
    </script></body></html>`;

    const gunView = new EventEmitter();
    // expose under a namespaced global for backwards-compatibility
    globalThis.__gun_webview_gunView = gunView;
    gunView._emit = gunView.emit.bind(gunView);
    // buffer events until the WebView connection is ready
    const _outQueue = [];
    gunView.emit = (ev, msg) => { _outQueue.push({ ev, msg }); };

    gunView.on('error', (e) => {
        console.error('[WEBVIEW]', 'Error event from webview:\n', e);
    });

    function WebViewComponent(initTimeout = 10000) {
        const webViewRef = React.createRef();
        let initAckTimer = null;
        return (<>
            <WebView
                key={'gun-webview-' + Math.random()}
                onError={a =>
                    console.log('[WEBVIEW]', 'error:', Object.keys(a), a.type, a.nativeEvent.description)
                }
                onMessage={ev => {
                    let parsed;
                    try {
                        parsed = JSON.parse(ev.nativeEvent.data);
                    } catch (e) {
                        console.error('[WEBVIEW] malformed message from webview', e);
                        return;
                    }
                    if (showIO)
                        console.log('[WEBVIEW]', 'Received event from webview:', parsed);
                    if (parsed.event == 'console') {
                        console[parsed.data.method]('[WEBVIEW]', ...parsed.data.args);
                        return;
                    }
                    // translate init-ack into a local ready event
                    if (parsed.event === 'init-ack') {
                        if (typeof initAckTimer !== 'undefined' && initAckTimer) {
                            clearTimeout(initAckTimer);
                            initAckTimer = null;
                        }
                        gunView._emit('ready');
                        return;
                    }
                    gunView._emit(parsed.event, parsed.data);
                }}
                onLoadEnd={() => {
                    gunView.emit = (ev, msg) => {
                        const e = { event: ev, data: msg || null };
                        if (showIO)
                            console.log('[WEBVIEW]', 'Sending event to webview:', e);
                        try {
                            webViewRef.current.postMessage(JSON.stringify(e));
                        } catch (e) {
                            console.error('[WEBVIEW]', 'postMessage failed', e);
                        }
                    };
                    // flush queued events
                    while (_outQueue.length) {
                        const q = _outQueue.shift();
                        gunView.emit(q.ev, q.msg);
                    }
                    // send explicit init handshake to the worker and wait for ack
                    gunView.emit('init');
                    // start init-ack timeout
                    initAckTimer = setTimeout(() => {
                        const ms = initTimeout || 10000;
                        console.error('[WEBVIEW] init-ack timeout after', ms, 'ms');
                        gunView._emit('error', new Error('webview init-ack timeout (' + ms + 'ms)'));
                        initAckTimer = null;
                    }, initTimeout || 10000);
                }}
                ref={webViewRef}
                originWhitelist={['*']}
                source={{ html: html, baseUrl: 'https://localhost' }}
            />
        </>);
    }

    return { WebViewComponent, gunView };
};