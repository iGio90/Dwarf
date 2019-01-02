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


var libc = Process.platform === "darwin" ? 'libSystem.B.dylib' : 'libc.so';
var dwarf = null;
var debug = false;

function getDwarf() {
    if (dwarf === null) {
        dwarf = new Dwarf();
    }

    return dwarf;
}

function Hook() {
    this.nativePtr = null;
    this.javaClassMethod = null;
    this.module = '';

    this.condition = null;
    this.logic = null;

    this.interceptor = null;
    this.javaOverloads = {}
}

function HookContext(tid) {
    this.tid = tid;
    this.hold_context = true;
    this.next_api = null;
    this.next_api_result = null;
    this.context = null;
}

function Dwarf() {
    function _DwarfApi() {
        this.deleteHook = function(key) {
            if (typeof key === 'number') {
                key = ptr(key);
            }

            var hook = getDwarf().hooks[key];
            if (typeof hook === 'undefined') {
                return;
            }
            if (hook.interceptor !== null) {
                hook.interceptor.detach();
                delete getDwarf().hooks[key];
            } else if (hook.javaClassMethod !== null) {
                api.hookJavaConstructor(hook.javaClassMethod, true);
                api.hookJavaMethod(hook.javaClassMethod, true);
                delete getDwarf().hooks[key];
            } else if (hook.module !== null) {
                delete getDwarf().onLoads(hook.module);
            }
        };

        this.enumerateExports = function(module) {
            return JSON.stringify(Module.enumerateExportsSync(module));
        };

        this.enumerateImports = function(module) {
            return JSON.stringify(Module.enumerateImportsSync(module));
        };

        this.enumerateSymbols = function(module) {
            return JSON.stringify(Module.enumerateSymbolsSync(module));
        };

        this.evaluate = function(w) {
            try {
                var res = eval(w);
                if (typeof res !== 'undefined') {
                    console.log(res);
                }
                return res;
            } catch (e) {
                return '';
            }
        };

        this.evaluateFunction = function (w) {
            try {
                var fn = new Function(w);
                return fn();
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

        this.findExport = function(name, module) {
            if (typeof module === 'undefined') {
                module = libc;
            }
            return Module.findExportByName(module, name);
        };

        this.findSymbol = function (pattern) {
            return DebugSymbol.findFunctionsMatching(pattern)
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

        this.getSymbolByAddress = function (pt) {
          try {
              pt = ptr(pt);
              return DebugSymbol.fromAddress(pt);
          } catch (e) {
              return {}
          }
        };

        this.javaBacktrace = function () {
            return Java.use("android.util.Log")
                .getStackTraceString(Java.use("java.lang.Exception").$new())
        };

        this.hookJava = function(what) {
            api.hookJavaMethod(what);
            api.hookJavaConstructor(what);
        };

        this.hookJavaConstructor = function(className, restore) {
            restore = typeof restore === 'undefined' ? false : restore;

            Java.perform(function () {
                var hook;
                try {
                    hook = Java.use(className);
                } catch (err) {
                    return;
                }

                var overloadCount = hook["$init"].overloads.length;

                if (overloadCount > 0) {
                    if (!restore) {
                        send('hook_java_callback:::' + className);
                        var h = new Hook();
                        h.javaClassMethod = className;
                        h.javaOverloads = [];
                        getDwarf().hooks[className] = h;
                    }

                    for (var i = 0; i < overloadCount; i++) {
                        var impl = null;
                        if (!restore) {

                            var mArgs = hook["$init"].overloads[i].argumentTypes;
                            h.javaOverloads[mArgs.length] = mArgs;

                            impl = function() {
                                var args = arguments;
                                var types = getDwarf().hooks[className].javaOverloads[args.length];
                                var newArgs = {};
                                for (var i=0;i<args.length;i++) {
                                    newArgs[i] = {
                                        arg: args[i],
                                        name: types[i]['name'],
                                        className: types[i]['className'],
                                    }
                                }

                                getDwarf()._onHook(className, newArgs, h);
                                return this["$init"].apply(this, args);
                            };
                        }
                        hook["$init"].overloads[i].implementation = impl;
                    }
                }
            });
        };

        this.hookJavaMethod = function(targetClassMethod, restore) {
            restore = typeof restore === 'undefined' ? false : restore;

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

                    if (!restore) {
                        send('hook_java_callback:::' + targetClassMethod);
                        var h = new Hook();
                        h.javaOverloads = [];
                        getDwarf().hooks[targetClassMethod] = h;
                    }

                    for (var i = 0; i < overloadCount; i++) {
                        var impl = null;
                        if (!restore) {
                            var mArgs = hook[targetMethod].overloads[i].argumentTypes;
                            h.javaOverloads[mArgs.length] = mArgs;

                            impl = function() {
                                var args = arguments;
                                var types = getDwarf().hooks[targetClassMethod].javaOverloads[args.length];
                                var newArgs = {};
                                for (var i=0;i<args.length;i++) {
                                    newArgs[i] = {
                                        arg: args[i],
                                        name: types[i]['name'],
                                        className: types[i]['className'],
                                    }
                                }

                                getDwarf()._onHook(targetClassMethod, newArgs, h);
                                return this[targetMethod].apply(this, args);
                            };
                        }
                        hook[targetMethod].overloads[i].implementation = impl;
                    }
                }
            });
        };

        this.hookNative = function(what, logic) {
            Interceptor.attach(what, logic);
        };

        this.hookOnLoad = function(m) {
            if (getDwarf().onLoads[m] === null || typeof(getDwarf().onLoads[m]) === 'undefined') {
                var hook = new Hook();
                hook.module = m;
                getDwarf().onLoads[m] = hook;
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

        this.nativeBacktrace = function(ctx) {
            return Thread.backtrace(ctx, Backtracer.ACCURATE)
                .map(DebugSymbol.fromAddress);
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
                    delete getDwarf().hook_contexts[t];
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

                var ActivityThread = Java.use('android.app.ActivityThread');
                var Context = Java.use('android.content.Context');
                var ctx = Java.cast(ActivityThread.currentApplication().getApplicationContext(), Context);

                var intent = ctx.getPackageManager().getLaunchIntentForPackage(
                    ctx.getPackageName());
                intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP['value']);
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK['value']);
                intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TASK ['value']);
                ctx.startActivity(intent);
            });
        };

        this.setHookCondition = function(pt, w) {
            try {
                var hook = null;
                try {
                    var tptr = ptr(pt);
                    hook = getDwarf().hooks[tptr];
                } catch (e) {}

                if (typeof hook === 'undefined' || hook === null) {
                    hook = getDwarf().onLoads[pt];
                }

                hook.condition = w;
                return true;
            } catch (e) {
                console.log(e);
                return false;
            }
        };

        this.setHookLogic = function(pt, w) {
            try {
                var hook = null;
                try {
                    var tptr = ptr(pt);
                    hook = getDwarf().hooks[tptr];
                } catch (e) {}

                if (typeof hook === 'undefined' || hook === null) {
                    hook = getDwarf().onLoads[pt];
                }
                if (typeof hook === 'undefined' || hook === null) {
                    return false;
                }
                hook.logic = w;
                return true;
            } catch (e) {
                console.log(e);
                return false;
            }
        };

        this.updateModules = function() {
            send('update_modules:::' + Process.getCurrentThreadId() + ':::' + JSON.stringify(Process.enumerateModulesSync()))
        };

        this.writeBytes = function(pt, what) {
            try {
                pt = ptr(pt);

                Memory.protect(pt, what.length, 'rwx');

                if (typeof what === 'string') {
                    Memory.writeByteArray(pt, getDwarf()._hex2a(hex));
                } else {
                    Memory.writeByteArray(pt, what);
                }
                return true;
            } catch (e) {
                api.log(e.toString());
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
    this.hook_contexts = {};
    this.hooks = {};
    this.onLoads = {};

    this._sendInfos = function(p, ctx) {
        var data = {
            "tid": Process.getCurrentThreadId()
        };
        if (ctx !== null) {
            data['context'] = ctx;
            if (typeof ctx['pc'] !== 'undefined') {
                data['symbol'] = DebugSymbol.fromAddress(ctx['pc']);
                data['backtrace'] = this.api.nativeBacktrace(ctx);
                data['ptr'] = p;
                data['is_java'] = false;
            } else {
                // java hook
                data['is_java'] = true;
                data['ptr'] = p;
                data['backtrace'] = this.api.javaBacktrace();
            }
        } else if (ctx === null) {
            data['pid'] = Process.id;
            data['arch'] = Process.arch;
            data["modules"] = Process.enumerateModulesSync('---');
            data["ranges"] = Process.enumerateRangesSync('---');
        }

        send('set_context:::' + JSON.stringify(data));
    };

    this._onHook = function(p, context, hook) {
        this.context = context;

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

        var shoulSleep = true;

        if (hook.logic !== null && typeof hook.logic !== 'undefined') {
            try {
                var logic = null;
                if (typeof hook.logic === 'string') {
                    logic = new Function(hook.logic);
                } else if (typeof hook.logic === 'function') {
                    logic = hook.logic;
                }
                if (logic !== null) {
                    console.log(logic);
                    shoulSleep = logic.apply(this, []) !== -1;
                }
            } catch (e) {
                console.log(e);
            }
        }

        this._sendInfos(p, context);
        var hc = new HookContext(Process.getCurrentThreadId());
        hc.context = context;
        this.hook_contexts[hc.tid] = hc;

        if (shoulSleep) {
            while (hc.hold_context) {
                if (hc.next_api !== null) {
                    hc.next_api_result = getDwarf().api[hc.next_api[0]].apply(this, hc.next_api[1]);
                    hc.next_api = null;
                }

                Thread.sleep(1 / 100);
            }
        }

        return this.context;
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
            var hook = null;
            wrappedInterceptor.attach(phdr_tgds_ptr, function (args) {
                if (hook !== null) {
                    send("onload_callback:::" + hook.module + ':::' + args[2] + ':::' + Process.getCurrentThreadId());
                    getDwarf()._onHook(this.context.pc, this.context, hook);
                    hook = null;
                }
            });
            wrappedInterceptor.attach(do_dlopen_ptr, function (args) {
                try {
                    var w = Memory.readCString(args[0]);
                    for (var s in getDwarf().onLoads) {
                        if (w.indexOf(s) >= 0) {
                            hook = getDwarf().onLoads[s];
                        }
                    }
                } catch (e) {}
            });
        }

        if (Java.available) {
            Java.perform(function () {
                var Application = Java.use('android.app.Application');
                Application.onCreate.overload().implementation = function () {
                    var hc = new HookContext(Process.getCurrentThreadId());
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
}

rpc.exports = {
    api: function(tid, api_funct, args) {
        if (typeof args === 'undefined' || args === null) {
            args = [];
        }

        if (getDwarf().hook_contexts.length > 0) {
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
        } else {
            return getDwarf().api[api_funct].apply(this, args)
        }
    },
};

if (!debug) {
    console.log = function(what) {
        if (what instanceof Object) {
            what = JSON.stringify(what);
        }
        api.log(what);
    };
}

var wrappedInterceptor = Interceptor;
var InterceptorWrapper = function() {
    this.attach = function (pt, logic) {
        try {
            var hook = new Hook();
            hook.nativePtr = ptr(pt);

            if (typeof logic === 'function') {
                hook.interceptor = wrappedInterceptor.attach(hook.nativePtr, function (args) {
                    logic.apply(this, args);
                    getDwarf()._onHook(hook.nativePtr, this.context, hook);
                });
            } else if (typeof logic === 'object') {
                hook.interceptor = wrappedInterceptor.attach(hook.nativePtr, {
                    onEnter: function (args) {
                        if (typeof logic['onEnter'] !== 'undefined') {
                            logic['onEnter'].apply(this, args);
                        }
                        getDwarf()._onHook(hook.nativePtr, this.context, hook);
                    },
                    onLeave: function (retval) {
                        if (typeof logic['onLeave'] !== 'undefined') {
                            logic['onLeave'].apply(this, retval);
                        }
                    }
                });
            } else {
                hook.interceptor = wrappedInterceptor.attach(hook.nativePtr, function (args) {
                    getDwarf()._onHook(hook.nativePtr, this.context, hook);
                });
            }

            getDwarf().hooks[hook.nativePtr] = hook;
            send('hook_native_callback:::' + hook.nativePtr);
            return true;
        } catch (e) {
            return false;
        }
    };
    this._attach = function(pt, cb) {
        return wrappedInterceptor._attach(pt, cb);
    };
    this.detachAll = function() {
        for (var hook in getDwarf().hooks) {
            api.deleteHook(hook);
        }
        return wrappedInterceptor.detachAll();
    };
    this.flush = function() {
        return wrappedInterceptor.flush();
    };
    this._replace = function(pt, nc, ret, args) {
        return wrappedInterceptor._replace(pt, nc, ret, args);
    };
    this.replace = function(pt, nc, ret, args) {
        return wrappedInterceptor.replace(pt, nc, ret, args);
    };
    this.revert = function(target) {
        return wrappedInterceptor.revert(target);
    };
};
Interceptor = new InterceptorWrapper();

/**
 Short hands api.
 Most of those are thought to handle ui/target data exchange
 **/
var api = getDwarf().api;

getDwarf().start();
getDwarf()._sendInfos(null, null);
