var javaAppContext = null;
var sleepingThreads = {};
var nativeFunctions = {};
var hooks = {};

var gettid = getNativeFunction(findExport('gettid'), 'int', []);

function log(what) {
    send('0:::' + what);
}

function sendInfos(ctx) {
    var data = {
        "modules": Process.enumerateModulesSync('---'),
        "ranges": Process.enumerateRangesSync('---'),
        "context": ctx,
        "tid": gettid()
    };
    if (typeof ctx['pc'] !== 'undefined') {
        data['symbol'] = DebugSymbol.fromAddress(ctx['pc']);
    } else {
        data['pid'] = Process.id;
        data['arch'] = Process.arch;
    }

    send('1:::' + JSON.stringify(data));
}

function onHook(p, context) {
    if (hooks[p]['c'] !== null) {
        try {
            var res = eval(hooks[p]['c']);
            if (res !== null && typeof(res) === 'boolean') {
                if (!res) {
                    return;
                }
            }
        } catch (e) {}
    }
    
    sendInfos(context);
    sleepingThreads[gettid()] = true;
    while (sleepingThreads[gettid()]) {
        Thread.sleep(1);
    }
}

function getNativeFunction(pt, ret, args) {
    var f = nativeFunctions[pt];
    if (typeof f !== 'undefined') {
        return f;
    }
    f = new NativeFunction(pt, ret, args);
    nativeFunctions[pt] = f;
    return f;
}

function findExport(name, module) {
    if (typeof module === 'undefined') {
        module = 'libc.so'
    }
    return Module.findExportByName(module, name);
}

Java.perform(function () {
    var Application = Java.use('android.app.Application');
    Application.onCreate.overload().implementation = function () {
        javaAppContext = this;
        sendInfos({});
        sleepingThreads[gettid()] = true;
        while (sleepingThreads[gettid()]) {
            Thread.sleep(1);
        }
        return this.onCreate();
    };
});

rpc.exports = {
    addvar: function(w) {
        try {
            var v = eval(w);
            var k = 2;
            if (v instanceof NativePointer) {
                k = 0;
            } else if (typeof(v) === 'string') {
                k = 1
            }
            return [v, k]
        } catch (e) {
            return [null, 0];
        }
    },
    getpt: function(w) {
        try {
            return ptr(eval(w));
        } catch (e) {
            return ptr(0);
        }
    },
    getrange: function(pt) {
        try {
            pt = ptr(pt);
            if (pt === null || pt === ptr(0)) {
                return []
            }
            return Process.findRangeByAddress(ptr(pt));
        } catch (e) {
            return []
        }
    },
    getvar: function(w) {
        return this[w];
    },
    hook: function(w) {
        try {
            var p = ptr(w);
            hooks[p] = {
                'i': Interceptor.attach(p, function () {
                    onHook(p, this.context);
                }),
                'c': null,
                'l': null
            };
            return true;
        } catch (e) {
            return false;
        }
    },
    hookcond: function(pt, w) {
        try {
            pt = ptr(pt);
            var obj = hooks[pt];
            if (typeof obj !== 'undefined' && obj !== null) {
                obj['c'] = w;
                return true;
            }
            return false;
        } catch (e) {
            return false;
        }
    },
    isvalidptr: function(pt) {
        try {
            var r = Process.findRangeByAddress(ptr(pt));
            return r !== null && typeof r !== 'undefined';
        } catch (e) {
            return false;
        }
    },
    memread: function(w, l) {
        try {
            w = ptr(w);
            return Memory.readByteArray(w, l);
        } catch (e) {
            return [];
        }
    },
    readptr: function(pt) {
        try {
            return Memory.readPointer(ptr(pt));
        } catch (e) {
            return ptr(0x0)
        }
    },
    readu8s: function(pt) {
        try {
            return Memory.readUtf8String(ptr(pt));
        } catch (e) {
            return ''
        }
    },
    release: function (tid) {
        if (typeof tid === 'undefined') {
            for (var t in sleepingThreads) {
                sleepingThreads[t] = false;
            }
        } else {
            var sleepingThread = sleepingThreads[tid];
            if (typeof sleepingThread !== 'undefined') {
                sleepingThread[tid] = false;
            }
        }
    },
    restart: function () {
        Java.perform(function () {
            var Intent = Java.use('android.content.Intent');
            var intent = javaAppContext.getPackageManager().getLaunchIntentForPackage(
                javaAppContext.getPackageName());
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP['value']);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK['value']);
            intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK ['value']);
            javaAppContext.startActivity(intent);
        });
    },
    ts: function (p) {
        try {
            var w = Memory.readPointer(ptr(p));
            var r = Process.findRangeByAddress(w);
            if (r !== null) {
                // valid pointer
                return [1, w];
            } else {
                try {
                    var s = Memory.readUtf8String(ptr(p));
                    if (s.length > 1) {
                        // valid string
                        return [0, w + ' (' + s + ')']
                    }
                } catch (e) {
                }
            }
        } catch (e) {
            return [-1, ''];
        }

        // int
        return [2, w];
    }
};