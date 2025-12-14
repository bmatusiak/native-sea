import { EventEmitter } from 'events';
import 'gun';
import 'gun/sea';

const webview = new EventEmitter();
webview._emit = webview.emit.bind(webview);
webview.emit = (ev, msg) => {
    // if (ev == 'message' || ev == 'console') {
    window.ReactNativeWebView.postMessage(JSON.stringify({ event: ev, data: msg || null }));
    // } else webview._emit(ev, msg);
};

window.addEventListener('message', function (event) {
    try {
        const ev = JSON.parse(event.data);
        webview._emit(ev.event, ev.data);
    } catch (e) {
        webview.emit('error', 'Malformed JSON in host message: ' + (e && e.stack || e));
    }
}, false);
document.addEventListener('message', function (event) {
    try {
        const ev = JSON.parse(event.data);
        webview._emit(ev.event, ev.data);
    } catch (e) {
        webview.emit('error', 'Malformed JSON in host message: ' + (e && e.stack || e));
    }
}, false);

//proxy console to react native over "console" event
['log', 'warn', 'error', 'info'].forEach((method) => {
    const original = console[method];
    console[method] = (...args) => {
        webview.emit('console', { method: method, args: args });
        original.apply(console, args);
    };
});

if (window._start) {
    webview.once('init', () => {
        try {
            window._start(webview);
        } catch (e) {
            webview.emit('error', e.stack || e.toString());
            return;
        }
        webview.emit('init-ack');
    });
} else {
    console.error('No _start function defined in webview!');
}