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

var dwarf = null;

function getDwarf() {
    if (dwarf === null) {
        dwarf = new Dwarf();
    }

    return dwarf;
}

function Hook() {
    this.nativePtr = null;
    this.javaClassMethod = null;

    this.context = null;
    this.condition = null;
    this.logic = null;

    this.interceptor = null;
}

function HookContext(tid) {
    this.tid = tid;
    this.hold_context = true;
    this.next_api = null;
    this.next_api_result = null;
}

function Dwarf() {
    function _DwarfApi() {
        this.evaluate = function(w) {
            try {
                return eval(w);
            } catch (e) {
                return '';
            }
        };

        this.evaluatePtr = function(w) {
            try {
                return ptr(eval(w));
            } catch (e) {
                return ptr(0);
            }
        };

        this.getAddressTs = function(p) {
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
        };

        this.getRange = function(pt) {
            try {
                pt = ptr(pt);
                if (pt === null || pt === ptr(0)) {
                    return []
                }
                return Process.findRangeByAddress(ptr(pt));
            } catch (e) {
                return []
            }
        };

        this.hookJavaMethod= function(targetClassMethod) {
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
                    var h = new Hook();
                    h.javaClassMethod = targetClassMethod;
                    getDwarf().hooks[targetClassMethod] = h;
                }
                for (var i = 0; i < overloadCount; i++) {
                    hook[targetMethod].overloads[i].implementation = function() {
                        var args = arguments;
                        getDwarf().hooks[targetClassMethod].context = args;
                        var newContext = getDwarf()._onHook(targetClassMethod, args);
                        if (newContext !== null) {
                            for (var k in this.context) {
                                args[k] = newContext[k];
                            }
                        }
                        return this[targetMethod].apply(this, args);
                    }
                }
            });
        };

        this.hookNative = function(w) {
            try {
                var hook = new Hook();
                hook.nativePtr = ptr(w);
                hook.interceptor = Interceptor.attach(hook.nativePtr, function () {
                    getDwarf().hooks[hook.nativePtr].context = this.context;
                    var newContext = getDwarf()._onHook(hook.nativePtr, this.context);
                    if (newContext !== null) {
                        for (var k in this.context) {
                            this.context[k] = newContext[k];
                        }
                    }
                    getDwarf().hooks[hook.nativePtr].context = this.context;
                });

                getDwarf().hooks[hook.nativePtr] = hook;
                send('hook_native_callback:::' + hook.nativePtr);
                return true;
            } catch (e) {
                return false;
            }
        };

        this.hookOnLoad = function(m) {
            if (getDwarf().onLoads[m] === null || typeof(getDwarf().onLoads[m]) === 'undefined') {
                getDwarf().onLoads[m] = {
                    'module': m,
                    'c': null,
                    'l': null,
                    'context': null,
                };
            }
        };

        this.isValidPointer = function(pt) {
            try {
                var r = Process.findRangeByAddress(ptr(pt));
                return r !== null && typeof r !== 'undefined';
            } catch (e) {
                return false;
            }
        };

        this.log = function(what) {
            send('log:::' + what);
        };

        this.readBytes = function(pt, l) {
            try {
                pt = ptr(pt);
                return Memory.readByteArray(pt, l);
            } catch (e) {
                return [];
            }
        };

        this.readPointer = function(pt) {
            try {
                return Memory.readPointer(ptr(pt));
            } catch (e) {
                return ptr(0x0)
            }
        };

        this.release = function(tid) {
            if (typeof tid === 'undefined') {
                for (var t in getDwarf().hook_contexts) {
                    getDwarf().hook_contexts[t].hold_context = false;
                }
            } else {
                var hc = getDwarf().hook_contexts[tid];
                if (typeof hc !== 'undefined') {
                    hc.hold_context = false;
                }
            }
        };

        this.restart = function() {
            Java.perform(function () {
                var Intent = Java.use('android.content.Intent');
                var intent = getDwarf().javaAppContext.getPackageManager().getLaunchIntentForPackage(
                    getDwarf().javaAppContext.getPackageName());
                intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP['value']);
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK['value']);
                intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK ['value']);
                getDwarf().javaAppContext.startActivity(intent);
            });
        };

        this.setContextValue = function(pt, key, val) {
            var ctx = null;
            try {
                ctx = getDwarf().hooks[ptr(pt)].context;
            } catch (e) {
                ctx = null;
            }
            if (ctx === null) {
                try {
                    ctx = getDwarf().hooks[pt].context;
                } catch (e) {}
            }
            if (ctx !== null) {
                ctx[key] = eval('\'' + val + '\'');
                return ctx[key]
            }

            return ptr(0);
        };

        this.setHookCondition = function(pt, w) {
            try {
                pt = ptr(pt);
                var hook = getDwarf().hooks[pt];
                if (typeof hook !== 'undefined' && hook !== null) {
                    hook.condition = w;
                    return true;
                }
                return false;
            } catch (e) {
                return false;
            }
        };

        this.setHookLogic = function(pt, w) {
            try {
                pt = ptr(pt);
                var hook = getDwarf().hooks[pt];
                if (typeof hook !== 'undefined' && hook !== null) {
                    hook.logic = new Function(w);
                    return true;
                }
                return false;
            } catch (e) {
                return false;
            }
        };

        this.updateModules = function() {
            send('update_modules:::' + getDwarf().gettid() + ':::' + JSON.stringify(Process.enumerateModulesSync()))
        };

        this.writeBytes = function(pt, hex) {
            try {
                pt = ptr(pt);
                Memory.writeByteArray(pt, getDwarf()._hex2a(hex));
                return true;
            } catch (e) {
                return false;
            }
        };

        this.writeUtf8 = function(pt, str) {
            try {
                pt = ptr(pt);
                Memory.writeUtf8String(pt, str);
                return true;
            } catch (e) {
                return false;
            }
        }
    }

    this.api = new _DwarfApi();
    this.javaAppContext = null;
    this.hook_contexts = {};
    this.hooks = {};
    this.onLoads = {};

    this.gettid = new NativeFunction(findExport('gettid'), 'int', []);

    this._sendInfos = function(p, ctx) {
        var data = {
            "tid": this.gettid()
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
    };

    this._onHook = function(p, context) {
        var hook = this.hooks[p];
        if (hook !== null && typeof(hook) !== 'undefined') {
            if (hook.condition !== null) {
                try {
                    var res = eval(hook.condition);
                    if (res !== null && typeof(res) === 'boolean') {
                        if (!res) {
                            return null;
                        }
                    }
                } catch (e) {}
            }

            if (hook.logic !== null) {
                try {
                    var logic = hook.logic;
                    var res = logic();
                    if (res !== null && res < 0) {
                        return null;
                    }
                } catch (e) {}
            }
        }

        this._sendInfos(p, context);
        var hc = new HookContext(this.gettid());
        this.hook_contexts[hc.tid] = hc;

        while (hc.hold_context) {
            if (hc.next_api !== null) {
                hc.next_api_result = getDwarf().api[hc.next_api[0]].apply(this, hc.next_api[1]);
                hc.next_api = null;
            }

            Thread.sleep(1 / 100);
        }

        if (hook !== null && typeof(hook) !== 'undefined') {
            return hook.context;
        } else {
            return null;
        }
    };

    this._hex2a = function(hex) {
        for (var bytes = [], c = 0; c < hex.length; c += 2)
            bytes.push(parseInt(hex.substr(c, 2), 16));
        return bytes;
    };

    this.start = function () {
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
            var phdr_tgds = new NativeFunction(phdr_tgds_ptr, 'void', ['pointer', 'int', 'pointer', 'pointer', 'pointer']);
            var hooked_onload = null;
            Interceptor.replace(phdr_tgds_ptr, new NativeCallback(function (a, b, c, d, e) {
                if (hooked_onload !== null) {
                    send("onload_callback:::" + hooked_onload['module'] + ':::' + c + ':::' + getDwarf().gettid());
                    hooked_onload['context'] = this.context;
                    var newContext = getDwarf()._onHook(this.context.pc, this.context);
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
                    for (var s in getDwarf().onLoads) {
                        if (w.indexOf(s) >= 0) {
                            hooked_onload = getDwarf().onLoads[s];
                        }
                    }
                } catch (e) {}
            });
        }

        Java.perform(function () {
            var Application = Java.use('android.app.Application');
            Application.onCreate.overload().implementation = function () {
                getDwarf().javaAppContext = this;
                getDwarf()._sendInfos(null, null);
                var hc = new HookContext(getDwarf().gettid());
                getDwarf().hook_contexts[hc.tid] = hc;
                while (hc.hold_context) {
                    if (hc.next_api !== null) {
                        hc.next_api_result = getDwarf().api[hc.next_api[0]].apply(this, hc.next_api[1]);
                        hc.next_api = null;
                    }

                    Thread.sleep(1 / 100);
                }
                return this.onCreate();
            };
        });
    }
}

rpc.exports = {
    api: function(tid, api_funct, args) {
        if (typeof args === 'undefined' || args === null) {
            args = [];
        }
        var hc = getDwarf().hook_contexts[tid];
        if (typeof hc !== 'undefined') {
            hc.next_api = [api_funct, args];
            while (hc.next_api_result === null) {
                Thread.sleep(1 / 100);
            }
            var ret = hc.next_api_result;
            hc.next_api_result = null;
            return ret;
        }
    }
};

/**
 Short hands api.
 Most of those are thought to handle ui/target data exchange
 **/

function findExport(name, module) {
    if (typeof module === 'undefined') {
        module = 'libc.so'
    }
    return Module.findExportByName(module, name);
}

getDwarf().start();