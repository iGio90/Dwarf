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
    this.module = '';

    this.condition = null;
    this.logic = null;

    this.interceptor = null;
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

        this.findExport = function(name, module) {
            if (typeof module === 'undefined') {
                module = 'libc.so'
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
                        getDwarf().hooks[className] = h;
                    }

                    for (var i = 0; i < overloadCount; i++) {
                        var impl = null;
                        if (!restore) {
                            impl = function() {
                                var args = arguments;
                                var newContext = getDwarf()._onHook(className, args, h);
                                if (newContext !== null) {
                                    for (var k in this.context) {
                                        args[k] = newContext[k];
                                    }
                                }
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
                            impl = function() {
                                var args = arguments;
                                var newContext = getDwarf()._onHook(targetClassMethod, args, h);
                                if (newContext !== null) {
                                    for (var k in this.context) {
                                        args[k] = newContext[k];
                                    }
                                }
                                return this[targetMethod].apply(this, args);
                            };
                        }
                        hook[targetMethod].overloads[i].implementation = impl;
                    }
                }
            });
        };

        this.hookNative = function(w) {
            try {
                var hook = new Hook();
                hook.nativePtr = ptr(w);
                hook.interceptor = Interceptor.attach(hook.nativePtr, function () {
                    var newContext = getDwarf()._onHook(hook.nativePtr, this.context, hook);
                    if (newContext !== null) {
                        for (var k in this.context) {
                            try {
                                var v = ptr(newContext[k]);
                                this.context[k] = v;
                            } catch (e) {}
                        }
                    }
                    if (typeof getDwarf().hook_contexts[getDwarf().gettid] !== 'undefined') {
                        getDwarf().hook_contexts[getDwarf().gettid].context = this.context;
                    }
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

    this.gettid = new NativeFunction(this.api.findExport('gettid'), 'int', []);

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

    this._onHook = function(p, context, hook) {
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
                var logic = new Function(hook.logic);
                logic.call({'context': context});
            } catch (e) {}
        }

        this._sendInfos(p, context);
        var hc = new HookContext(this.gettid());
        hc.context = context;
        this.hook_contexts[hc.tid] = hc;

        while (hc.hold_context) {
            if (hc.next_api !== null) {
                hc.next_api_result = getDwarf().api[hc.next_api[0]].apply(this, hc.next_api[1]);
                hc.next_api = null;
            }

            Thread.sleep(1 / 100);
        }

        return hc.context;
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
            var hook = null;
            Interceptor.replace(phdr_tgds_ptr, new NativeCallback(function (a, b, c, d, e) {
                if (hook !== null) {
                    send("onload_callback:::" + hook.module + ':::' + c + ':::' + getDwarf().gettid());
                    var newContext = getDwarf()._onHook(this.context.pc, this.context, hook);
                    if (newContext != null) {
                        for (var k in this.context) {
                            try {
                                var v = ptr(newContext[k]);
                                this.context[k] = v;
                            } catch (e) {}
                        }
                    }
                    if (typeof getDwarf().hook_contexts[getDwarf().gettid] !== 'undefined') {
                        getDwarf().hook_contexts[getDwarf().gettid].context = this.context;
                    }
                    hook = null;
                }
                return phdr_tgds(a, b, c, d, e);
            }, 'void', ['pointer', 'int', 'pointer', 'pointer', 'pointer']));
            Interceptor.attach(do_dlopen_ptr, function (args) {
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
var api = getDwarf().api;

getDwarf().start();