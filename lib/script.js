/**
    Dwarf - Copyright (C) 2018 iGio90

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>
**/

var javaAppContext = null;
var sleepingThreads = {};
var nativeFunctions = {};
var hooks = {};
var onLoads = [];

var gettid = _getNativeFunction(findExport('gettid'), 'int', []);

function _log(what) {
    send('log:::' + what);
}

function _sendInfos(p, ctx) {
    var data = {
        "tid": gettid()
    };
    if (ctx !== null) {
        data['context'] = ctx;
        if (typeof ctx['pc'] !== 'undefined') {
            data['symbol'] = DebugSymbol.fromAddress(ctx['pc']);
            data['backtrace'] = Thread.backtrace(ctx, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress);
            data['ptr'] = p;
            data['is_java'] = false;
        } else {
            // java hook
            data['is_java'] = true;
            data['ptr'] = p;
            data['backtrace'] = Java.use("android.util.Log")
                .getStackTraceString(Java.use("java.lang.Exception").$new());
        }
    } else if (ctx === null) {
        data['pid'] = Process.id;
        data['arch'] = Process.arch;
        data["modules"] = Process.enumerateModulesSync('---');
        data["ranges"] = Process.enumerateRangesSync('---');
    }

    send('set_context:::' + JSON.stringify(data));
}

function _onHook(p, context) {
    var hook_info = hooks[p];
    if (hook_info !== null && typeof(hook_info) !== 'undefined') {
        if (hook_info['c'] !== null) {
            try {
                var res = eval(hook_info['c']);
                if (res !== null && typeof(res) === 'boolean') {
                    if (!res) {
                        return null;
                    }
                }
            } catch (e) {}
        }

        if (hook_info['l'] !== null) {
            try {
                var res = hook_info['l']();
                if (res !== null && res < 0) {
                    return null;
                }
            } catch (e) {}
        }
    }

    _sendInfos(p, context);
    sleepingThreads[gettid()] = true;

    console.log('1 -> ' + gettid());

    while (sleepingThreads[gettid()]) {
        Thread.sleep(1);
    }
    if (hook_info !== null && typeof(hook_info) !== 'undefined') {
        return hook_info['context'];
    } else {
        return null;
    }
}

function _getNativeFunction(pt, ret, args) {
    var f = nativeFunctions[pt];
    if (typeof f !== 'undefined') {
        return f;
    }
    f = new NativeFunction(pt, ret, args);
    nativeFunctions[pt] = f;
    return f;
}

function _hex2a(hex) {
    for (var bytes = [], c = 0; c < hex.length; c += 2)
        bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}

var symb = Module.enumerateSymbolsSync("linker");
var phdr_tgds_ptr = 0;
var do_dlopen_ptr = 0;
for (var sym in symb) {
    if (symb[sym].name.indexOf("phdr_table_get_dynamic_section") >= 0) {
        phdr_tgds_ptr = symb[sym].address
    } else if(symb[sym].name.indexOf('do_dlopen') >= 0) {
        do_dlopen_ptr = symb[sym].address;
    }
    if (phdr_tgds_ptr > 0 && do_dlopen_ptr > 0) {
        break;
    }
}
if (phdr_tgds_ptr > 0 && do_dlopen_ptr > 0) {
    var phdr_tgds = _getNativeFunction(phdr_tgds_ptr, 'void', ['pointer', 'int', 'pointer', 'pointer', 'pointer']);
    var hooked_onload = null;
    Interceptor.replace(phdr_tgds_ptr, new NativeCallback(function (a, b, c, d, e) {
        if (hooked_onload !== null) {
            send("onload_callback:::" + hooked_onload['module'] + ':::' + c + ':::' + gettid());
            hooked_onload['context'] = this.context;
            var newContext = _onHook(this.context.pc, this.context);
            if (newContext != null) {
                this.context = newContext;
            }
            hooked_onload['context'] = this.context;
            hooked_onload = null;
        }
        return phdr_tgds(a, b, c, d, e);
    }, 'void', ['pointer', 'int', 'pointer', 'pointer', 'pointer']));
    Interceptor.attach(do_dlopen_ptr, function (args) {
        try {
            var w = Memory.readCString(args[0]);
            for (var s in onLoads) {
                if (w.indexOf(s) >= 0) {
                    hooked_onload = onLoads[s];
                }
            }
        } catch (e) {}
    });
}

Java.perform(function () {
    var Application = Java.use('android.app.Application');
    Application.onCreate.overload().implementation = function () {
        javaAppContext = this;
        _sendInfos(null, null);
        sleepingThreads[gettid()] = true;
        while (sleepingThreads[gettid()]) {
            Thread.sleep(1);
        }
        return this.onCreate();
    };
});

rpc.exports = {
    evaluate: function(w) {
        try {
            return eval(w);
        } catch (e) {
            return '';
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
        return hookNative(w);
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
    hooklogic: function(pt, w) {
        try {
            pt = ptr(pt);
            var obj = hooks[pt];
            if (typeof obj !== 'undefined' && obj !== null) {
                obj['l'] = new Function(w);
                return true;
            }
            return false;
        } catch (e) {
            return false;
        }
    },
    invoke: function(exp, args) {
        return rpc.exports[exp].apply(this, args);
    },
    isvalidptr: function(pt) {
        try {
            var r = Process.findRangeByAddress(ptr(pt));
            return r !== null && typeof r !== 'undefined';
        } catch (e) {
            return false;
        }
    },
    jmh: function(w) {
        return hookJavaMethod(w);
    },
    memread: function(pt, l) {
        try {
            pt = ptr(pt);
            return Memory.readByteArray(pt, l);
        } catch (e) {
            return [];
        }
    },
    onload: function(m) {
        if (onLoads[m] === null || typeof(onLoads[m]) === 'undefined') {
            onLoads[m] = {
                'module': m,
                'c': null,
                'l': null,
                'context': null
            };
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
    setcontextval: function(pt, key, val) {
        var ctx = null;
        try {
            ctx = hooks[ptr(pt)]['context'];
        } catch (e) {
            ctx = null;
        }
        if (ctx === null) {
            try {
                ctx = hooks[pt]['context'];
            } catch (e) {}
        }
        if (ctx === null) {
            try {
                ctx = onLoads[pt]['context'];
            } catch (e) {}
        }
        if (ctx !== null) {
            ctx[key] = eval('\'' + val + '\'');
            return ctx[key]
        }

        return ptr(0);
    },
    ts: function (p) {
        try {
            var w = Memory.readPointer(ptr(p));
            var r = Process.findRangeByAddress(w);
            if (r !== null) {
                try {
                    var s = Memory.readUtf8String(ptr(p));
                    if (s.length > 1) {
                        // valid string
                        return [0, s]
                    }
                } catch (e) {}

                // valid pointer
                return [1, w];
            } else {
                try {
                    var s = Memory.readUtf8String(ptr(p));
                    if (s.length > 1) {
                        // valid string
                        return [0,  s]
                    }
                } catch (e) {
                }
            }
        } catch (e) {
            return [-1, ''];
        }

        // int
        return [2, w];
    },
    updtmdl: function() {
        updateModules();
    },
    writebytes: function(pt, hex) {
        try {
            pt = ptr(pt);
            Memory.writeByteArray(pt, _hex2a(hex));
            return true;
        } catch (e) {
            return false;
        }
    },
    writeutf8: function (pt, str) {
        try {
            pt = ptr(pt);
            Memory.writeUtf8String(pt, str);
            return true;
        } catch (e) {
            return false;
        }
    }
};

/**
 Short hands api.
 Most of those are thought to handle ui/target data exchange
 **/

function findExport(name, module) {
    console.log('1 -> ' + gettid());
    if (typeof module === 'undefined') {
        module = 'libc.so'
    }
    return Module.findExportByName(module, name);
}

function hookJavaMethod(targetClassMethod) {
    Java.perform(function () {
        var delim = targetClassMethod.lastIndexOf(".");
        if (delim === -1) return;

        var targetClass = targetClassMethod.slice(0, delim);
        var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length);

        var hook;
        try {
            hook = Java.use(targetClass);
        } catch (err) {
            return;
        }

        if (typeof hook[targetMethod] === 'undefined') {
            return;
        }

        var overloadCount = hook[targetMethod].overloads.length;
        if (overloadCount > 0) {
            send('hook_java_callback:::' + targetClassMethod);
            hooks[targetClassMethod] = {
                'i': null,
                'c': null,
                'l': null,
                'context': null
            }
        }
        for (var i = 0; i < overloadCount; i++) {
            hook[targetMethod].overloads[i].implementation = function() {
                var args = arguments;
                hooks[targetClassMethod]['context'] = args;
                var newContext = _onHook(targetClassMethod, args);
                if (newContext !== null) {
                    for (var k in this.context) {
                        args[k] = newContext[k];
                    }
                }
                return this[targetMethod].apply(this, args);
            }
        }
    });
}

function hookNative(w) {
    try {
        var p = ptr(w);
        hooks[p] = {
            'i': Interceptor.attach(p, function () {
                hooks[p]['context'] = this.context;
                var newContext = _onHook(p, this.context);
                if (newContext !== null) {
                    for (var k in this.context) {
                        this.context[k] = newContext[k];
                    }
                }
                hooks[p]['context'] = this.context;
            }),
            'c': null,
            'l': null,
            'context': null
        };
        send('hook_native_callback:::' + p);
        return true;
    } catch (e) {
        return false;
    }
}

function updateModules() {
    send('update_modules:::' + JSON.stringify(Process.enumerateModulesSync()))
}