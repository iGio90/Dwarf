/**
 Dwarf - Copyright (C) 2019 Giovanni Rocca (iGio90)

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

/**
 * those are meant to be exposed
 */
var api = null;
var dwarf = null;
var fs = null;
var kernel = null;
var javaHelper = null;

var REASON_SET_INITIAL_CONTEXT = 0;
var REASON_HOOK = 0;
var REASON_WATCHER = 1;

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
    this.context = null;
    this.java_handle = null;

    this.next_api = null;
    this.next_api_result = 'dwarf_handler';
}

function Dwarf() {
    this.hook_contexts = {};
    this.hooks = {};
    this.onLoads = {};
    this.java_handlers = {};
    this.memory_watchers = {};

    this._handleException = function(exception) {
        var tid = Process.getCurrentThreadId();
        var address = exception['address'];
        var watcher = null;

        // watchers
        if (Object.keys(getDwarf().memory_watchers).length > 0) {
            // make sure it's access violation
            if (exception['type'] === 'access-violation') {
                watcher = getDwarf().memory_watchers[exception['memory']['address']];
                if (typeof watcher !== 'undefined') {
                    watcher.restore();
                    send('watcher:::' + JSON.stringify(exception) + ':::' + tid);
                } else {
                    watcher = null;
                }
            }
        }

        if (watcher !== null) {
            var hook = new Hook();
            hook.nativePtr = address;
            hook.interceptor = wrappedInterceptor.attach(address, function () {
                getDwarf()._onHook(REASON_WATCHER, hook.nativePtr, this.context, hook, null);
                watcher.watch();
                hook.interceptor.detach();
            });

        }
        return watcher !== null;
    };

    this._hex2a = function(hex) {
        for (var bytes = [], c = 0; c < hex.length; c += 2)
            bytes.push(parseInt(hex.substr(c, 2), 16));
        return bytes;
    };

    this.uniqueBy = function(array, key) {
        var seen = {};
        return array.filter(function(item) {
            var k = key(item);
            return seen.hasOwnProperty(k) ? false : (seen[k] = true);
        });
    };

    this._onHook = function(reason, p, context, hook, java_handle) {
        var that = {};
        that['context'] = context;
        that['handle'] = java_handle;

        if (hook.condition !== null) {
            try {
                this.context = that['context'];
                var res = eval(hook.condition);
                if (res !== null && typeof(res) === 'boolean') {
                    if (!res) {
                        return null;
                    }
                }
            } catch (e) {}
        }

        var shouldSleep = true;

        if (hook.logic !== null && typeof hook.logic !== 'undefined') {
            try {
                var logic = null;
                if (typeof hook.logic === 'string') {
                    logic = new Function(hook.logic);
                } else if (typeof hook.logic === 'function') {
                    logic = hook.logic;
                }
                if (logic !== null) {
                    var ret = logic.apply(that, []);
                    if (typeof ret !== 'undefined') {
                        shouldSleep = ret !== -1;
                    }
                }
            } catch (e) {
                console.log(e);
            }
        }

        if (shouldSleep) {
            this._sendInfos(reason, p, context);
            var hc = new HookContext(Process.getCurrentThreadId());
            hc.context = context;
            hc.java_handle = java_handle;
            this.hook_contexts[hc.tid] = hc;
            that['hook_context'] = hc;

            while (hc.hold_context) {
                if (hc.next_api !== null) {
                    hc.next_api_result = api[hc.next_api[0]].apply(that, hc.next_api[1]);
                    hc.next_api = null;
                }
                Thread.sleep(1 / 100);
            }
            delete this.hook_contexts[hc.tid];
        }
        return this.context;
    };

    this._sendInfos = function(reason, p, ctx) {
        var tid;
        if (p === null && ctx === null) {
            tid = Process.id;
        } else {
            tid = Process.getCurrentThreadId();
        }
        var data = {
            "tid": tid,
            "reason": reason
        };

        var bt = null;

        if (ctx !== null) {
            data['context'] = ctx;
            if (typeof ctx['pc'] !== 'undefined') {
                var symb;
                try {
                    symb = DebugSymbol.fromAddress(ctx['pc']);
                } catch (e) {}
                if (symb === null || typeof symb === 'undefined') {
                    symb = {};
                }
                data['symbol'] = symb;
                bt = {'bt': api.nativeBacktrace(ctx), 'type': 'native'};
                data['ptr'] = p;
                data['is_java'] = false;

                var newCtx = {};
                for (var reg in ctx)  {
                    var val = ctx[reg];
                    var isValidPtr = api.isValidPointer(val);
                    var ts = null;
                    if (isValidPtr) {
                        ts = api.getAddressTs(val);
                    }
                    newCtx[reg] = {
                        'value': val,
                        'isValidPointer': isValidPtr,
                        'telescope': ts
                    };
                    data['context'] = newCtx;
                }
            } else {
                // java hook
                data['is_java'] = true;
                data['ptr'] = p;
                bt = {'bt': api.javaBacktrace(), 'type': 'java'};
            }
        } else if (ctx === null) {
            data['pid'] = Process.id;
            data['arch'] = Process.arch;
            data['modules'] = Process.enumerateModulesSync();
            data['ranges'] = Process.enumerateRangesSync('---');
            data['java'] = Java.available;
        }

        send('set_context:::' + JSON.stringify(data));
        if (bt !== null) {
            send('backtrace:::' + JSON.stringify(bt))
        }
    };

    this.start = function () {
        Process.setExceptionHandler(getDwarf()._handleException);

        var symb = Module.enumerateSymbolsSync(Process.arch.indexOf('64') >= 0 ? 'linker64' : "linker");
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
                    getDwarf()._onHook(REASON_HOOK, this.context.pc, this.context, hook, null);
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
    };

    if (Java.available) {
        try {
            // wrap in a try catch because Java.perform fail on some processes (i.e zygote)
            Java.perform(function () {
                // initialize Java helper
                javaHelper = new JavaHelper();

                var Application = Java.use('android.app.Application');
                Application.onCreate.overload().implementation = function () {
                    var hc = new HookContext(Process.id);
                    getDwarf().hook_contexts[Process.id] = hc;

                    while (hc.hold_context) {
                        if (hc.next_api !== null) {
                            hc.next_api_result = api[hc.next_api[0]].apply(this, hc.next_api[1]);
                            hc.next_api = null;
                        }

                        Thread.sleep(1 / 100);
                    }
                    delete getDwarf().hook_contexts[hc.tid];
                    return this.onCreate();
                };
                Application.$dispose();
            });
        } catch (e) {}
    }
}

function DwarfApi() {
    this._traced_tid = 0;

    this._detach = function() {
        for (var h in getDwarf().hooks) {
            var hook = getDwarf().hooks[h];
            if (hook.interceptor !== null) {
                hook.interceptor.detach();
            }
        }
        wrappedInterceptor.detachAll();
        api.release();
        // wait all contexts to be released
    };

    this.addWatcher = function(pt) {
        pt = ptr(pt);
        if (typeof getDwarf().memory_watchers[pt] === 'undefined') {
            var range = Process.findRangeByAddress(pt);
            if (range === null) {
                return;
            }
            getDwarf().memory_watchers[pt] = new MemoryWatcher(pt, range.protection);
            send('watcher_added:::' + pt);
        }
        getDwarf().memory_watchers[pt].watch();
    };

    this.deleteHook = function(key) {
        if (typeof key === 'number') {
            key = ptr(key);
        } else if (typeof key === 'string' && key.startsWith('0x')) {
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
            api.hookJavaConstructor(hook.javaClassMethod, null, true);
            api.hookJavaMethod(hook.javaClassMethod, null, true);
            delete getDwarf().hooks[key];
        } else if (hook.module !== null) {
            delete getDwarf().onLoads[hook.module];
        }
    };

    this.enumerateExports = function(module) {
        return JSON.stringify(Module.enumerateExportsSync(module));
    };

    this.enumerateImports = function(module) {
        return JSON.stringify(Module.enumerateImportsSync(module));
    };

    this.enumerateJavaClasses = function() {
        Java.perform(function() {
            send('enumerate_java_classes_start:::');
            Java.enumerateLoadedClasses({
                onMatch: function(className) {
                    send('enumerate_java_classes_match:::' + className);
                },
                onComplete: function() {
                    send('enumerate_java_classes_complete:::');
                }
            })
        });
    };

    this.enumerateJavaMethods = function(className) {
        if (Java.available) {
            Java.perform(function () {
                // 0xdea code -> https://github.com/0xdea/frida-scripts/blob/master/raptor_frida_android_trace.js
                var clazz = Java.use(className);
                var methods = clazz.class.getDeclaredMethods();
                clazz.$dispose();

                var parsedMethods = [];
                methods.forEach(function(method) {
                    parsedMethods.push(method.toString().replace(className + ".",
                        "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
                });
                var result = getDwarf().uniqueBy(parsedMethods, JSON.stringify);
                send('enumerate_java_methods_complete:::' + className + ':::' +
                    JSON.stringify(result));
            });
        }
    };

    this.enumerateSymbols = function(module) {
        return JSON.stringify(Module.enumerateSymbolsSync(module));
    };

    this.evaluate = function(w, nolog) {
        if (typeof nolog !== 'boolean') {
            nolog = false;
        }
        try {
            var res = eval(w);
            if (!nolog && typeof res !== 'undefined') {
                console.log(res);
            }
            return res;
        } catch (e) {
            console.log(e.toString());
            return '';
        }
    };

    this.evaluateFunction = function(w) {
        try {
            var fn = new Function(w);
            return fn.apply(this, []);
        } catch (e) {
            console.log(e.toString());
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

    this.findSymbol = function(pattern) {
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

    this.getSymbolByAddress = function(pt) {
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

    this.hookAllJavaMethods = function(className) {
        if (!Java.available) {
            return false;
        }

        Java.perform(function () {
            var clazz = Java.use(className);
            var methods = clazz.class.getDeclaredMethods();

            var parsedMethods = [];
            methods.forEach(function(method) {
                parsedMethods.push(method.toString().replace(className + ".",
                    "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
            });
            var result = getDwarf().uniqueBy(parsedMethods, JSON.stringify);
            result.forEach(function (method) {
                api.hookJavaMethod(className + '.' + method);
            });
            clazz.$dispose();
        });
    };

    this.hookJava = function(what, impl) {
        api.hookJavaMethod(what, impl);
        api.hookJavaConstructor(what, impl);
    };

    this.hookJavaConstructor = function(className, implementation, restore) {
        if (!Java.available) {
            return;
        }
        restore = typeof restore === 'undefined' ? false : restore;
        javaHelper.hook(className, '$init', implementation, restore);
    };

    this.hookJavaMethod = function(targetClassMethod, implementation, restore) {
        if (!Java.available) {
            return false;
        }
        restore = typeof restore === 'undefined' ? false : restore;
        var delim = targetClassMethod.lastIndexOf(".");
        if (delim === -1) return;

        var targetClass = targetClassMethod.slice(0, delim);
        var targetMethod = targetClassMethod.slice(delim + 1, targetClassMethod.length);
        javaHelper.hook(targetClass, targetMethod, implementation, restore);
    };

    this.hookNative = function(what, logic) {
        Interceptor.attach(what, logic);
    };

    this.hookOnLoad = function(m, logic) {
        if (getDwarf().onLoads[m] === null || typeof(getDwarf().onLoads[m]) === 'undefined') {
            var hook = new Hook();
            hook.module = m;
            if (typeof logic !== 'undefined') {
                hook.logic = logic;
            }
            getDwarf().onLoads[m] = hook;
            send('hook_onload_callback:::' + m)
        }
    };

    this.isAddressWatched = function(pt) {
        var watcher = getDwarf().memory_watchers[ptr(pt)];
        return typeof watcher !== 'undefined';
    };

    this.isValidPointer = function(pt) {
        try {
            var r = Process.findRangeByAddress(ptr(pt));
            return r !== null && typeof r !== 'undefined';
        } catch (e) {
            return false;
        }
    };

    this.javaExplorer = function(what) {
        if (typeof this['hook_context'] === 'undefined') {
            console.log('Explorer outside context scope');
            return null;
        } else {
            var handle;
            if (typeof what === 'number') {
                if (what >= 0) {
                    var hc = this['hook_context'];
                    var arg = hc['context'][what];
                    if (arg === null || typeof arg['handle'] === 'undefined') {
                        return null;
                    }
                    handle = arg['handle'];
                } else {
                    handle = this['hook_context']['java_handle']
                }
            } else if (typeof what === 'object') {
                if (typeof what['handle_class'] !== 'undefined') {
                    var cl = Java.use(what['handle_class']);
                    handle = what['handle'];
                    if (typeof handle === 'string') {
                        handle = getDwarf().java_handlers[handle];
                        if (typeof handle === 'undefined') {
                            return null;
                        }
                    } else if (typeof handle === 'object') {
                        try {
                            handle = Java.cast(ptr(handle['$handle']), cl);
                        } catch (e) {
                            return null;
                        }
                    } else {
                        try {
                            handle = Java.cast(ptr(handle), cl);
                        } catch (e) {
                            return null;
                        }
                    }
                    cl.$dispose();
                } else {
                    handle = what;
                }
            } else {
                console.log('Explorer handle not found');
                return {};
            }
            var ol;
            try {
                ol = Object.getOwnPropertyNames(handle.__proto__);
            } catch (e) {
                return null;
            }
            var clazz = '';
            if (typeof handle['$className'] !== 'undefined') {
                clazz = handle['$className'];
            }
            var ret = {
                'class': clazz,
                'data': {}
            };
            for (var o in ol) {
                var name = ol[o];
                try {
                    var t = typeof handle[name];
                    var value = '';
                    var overloads = [];
                    var sub_handle = null;
                    var sub_handle_class = '';
                    if (t === 'function') {
                        var overloadCount = handle[name].overloads.length;
                        if (overloadCount > 0) {
                            for (var i in handle[name].overloads) {
                                overloads.push({
                                    'args': handle[name].overloads[i].argumentTypes,
                                    'return': handle[name].overloads[i].returnType
                                });
                            }
                        }
                    } else if (t === 'object') {
                        sub_handle_class = handle[name]['$className'];
                        if (typeof handle[name]['$handle'] !== 'undefined' && handle[name]['$handle'] !== null) {
                            value = handle[name]['$handle'];
                            sub_handle = handle[name]['$handle'];
                        } else {
                            sub_handle_class = handle[name]['value']['$className'];
                            if (typeof handle[name]['value'] === 'object') {

                                if (typeof handle[name]['fieldReturnType'] !== 'undefined') {
                                    sub_handle = handle[name]['value'];
                                    if (typeof sub_handle['$handle'] !== 'undefined') {
                                        var pt = sub_handle['$handle'];
                                        getDwarf().java_handlers[pt] = sub_handle;
                                        sub_handle = pt;
                                        value = handle[name]['fieldReturnType']['className'];
                                        sub_handle_class = value;
                                    } else {
                                        if (handle[name]['fieldReturnType']['type'] !== 'pointer') {
                                            t = handle[name]['fieldReturnType']['type'];
                                            sub_handle_class = handle[name]['fieldReturnType']['className'];
                                            value = sub_handle_class;
                                        } else {
                                            _log('Explorer met unsupported handle type');
                                            _log(JSON.stringify(handle[name]));
                                            _log(JSON.stringify(handle[name]['fieldReturnType']));
                                            continue;
                                        }
                                    }
                                } else {
                                    value = handle[name]['value'].toString();
                                    t = typeof (value);
                                }
                            } else {
                                t = typeof(handle[name]['value']);
                                value = handle[name]['value'].toString();
                            }
                        }
                    } else {
                        value = handle[name];
                    }

                    ret['data'][name] = {
                        'value': value,
                        'handle': sub_handle,
                        'handle_class': sub_handle_class,
                        'type': t,
                        'overloads': overloads,
                    };
                } catch (e) {}
            }
            return ret;
        }
    };

    this.log = function(what) {
        send('log:::' + what);
    };

    this.nativeBacktrace = function(ctx) {
        return Thread.backtrace(ctx, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress);
    };

    this.memoryScan = function(pattern) {
        var ranges = [];
        Process.enumerateRanges('r--', {
            onMatch: function(range) {
                ranges.push(range);
            },
            onComplete: function() {
                var k = ranges.length;
                for (var i in ranges) {
                    var range = ranges[i];
                    try {
                        Memory.scan(range.base, range.size, pattern, {
                            onMatch: function(address, size) {
                                var d = DebugSymbol.fromAddress(address);
                                if (d === null || typeof d === 'undefined') {
                                    d = {};
                                }
                                send('memory_scan_match:::' + pattern + ':::' +
                                    address + ':::' + JSON.stringify(d));
                            },
                            onError: function(reason) {
                                console.log(reason);
                                k--;
                            },
                            onComplete: function() {
                                k--;
                                if (k === 0) {
                                    send('memory_scan_complete:::' + pattern);
                                }
                            }
                        });
                    } catch (e) {
                        console.log(e);
                        send('memory_scan_finished:::');
                        return;
                    }
                }
            }
        });
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
        if (typeof tid === 'undefined' || tid < 1) {
            for (var t in getDwarf().hook_contexts) {
                console.log('resuming := ' + getDwarf().hook_contexts[t].tid);
                getDwarf().hook_contexts[t].hold_context = false;
            }
        } else {
            var hc = getDwarf().hook_contexts[tid];
            if (typeof hc !== 'undefined') {
                console.log('resuming := ' + hc.tid);
                hc.hold_context = false;
            }
        }
    };

    this.removeWatcher = function(pt) {
        pt = ptr(pt);
        var watcher = getDwarf().memory_watchers[pt];
        if (typeof watcher !== 'undefined') {
            watcher.restore();
            delete getDwarf().memory_watchers[pt];
            send('watcher_removed:::' + pt);
            return true;
        }
        return false;
    };

    this.restart = function() {
        if (Java.available) {
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

                Intent.$dispose();
                ActivityThread.$dispose();
                Context.$dispose();
            });
        }
    };

    this.setData = function (key, data) {
        if (typeof key !== 'string' && key.length < 1) {
            return;
        }

        if (data.constructor.name === 'ArrayBuffer') {
            send('set_data:::' + key, data)
        } else {
            if (data.constructor.name === 'Object') {
                data = JSON.stringify(data,null,4);
            }
            send('set_data:::' + key + ':::' + data)
        }
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

    this.startJavaTracer = function(classes) {
        if (javaHelper !== null) {
            return javaHelper.startTrace(classes);
        }
        return false;
    };

    this.startNativeTracer = function(tid) {
        if (this._traced_tid > 0) {
            return false;
        }

        this._traced_tid = tid;
        Stalker.queueDrainInterval = 5;
        Stalker.follow(this._traced_tid, {
            events: {
                call: true,
                ret: false,
                exec: false,
                block: false,
                compile: false
            },

            onReceive: function(events) {
                send('tracer:::' + Stalker.parse(events, {
                    annotate: true,
                    stringify: true
                }));
            }
        });

        return true;
    };

    this.stopJavaTracer = function() {
        if (javaHelper !== null) {
            return javaHelper.stopTrace();
        }
        return false;
    };

    this.stopNativeTracer = function() {
        if (this._traced_tid > 0) {
            Stalker.unfollow(this._traced_tid);
            Stalker.garbageCollect();
            this._traced_tid = 0;
            return true;
        }
        return false;
    };

    this.updateModules = function() {
        send('update_modules:::' + Process.getCurrentThreadId() + ':::' +
            JSON.stringify(Process.enumerateModulesSync()))
    };

    this.updateRanges = function() {
        try {
            send('update_ranges:::' + Process.getCurrentThreadId() + ':::' +
                JSON.stringify(Process.enumerateRangesSync()))
        } catch (e) {
            console.log('failed to update ranged. err: ' + e);
        }
    };

    this.writeBytes = function(pt, what) {
        try {
            pt = ptr(pt);

            Memory.protect(pt, what.length, 'rwx');

            if (typeof what === 'string') {
                api.writeUtf8(pt, fromHexString());
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

function DwarfFs() {
    this.fclose = new NativeFunction(api.findExport('fclose'), 'int', ['pointer']);
    this.fcntl = new NativeFunction(api.findExport('fcntl'), 'int', ['int', 'int', 'int']);
    this.fgets = new NativeFunction(api.findExport('fgets'), 'int', ['pointer', 'int', 'pointer']);
    this.fileno = new NativeFunction(api.findExport('fileno'), 'int', ['pointer']);
    this.fputs = new NativeFunction(api.findExport('fputs'), 'int', ['pointer', 'pointer']);
    this.getline = new NativeFunction(api.findExport('getline'), 'int', ['pointer', 'pointer', 'pointer']);
    this.pclose = new NativeFunction(api.findExport('pclose'), 'int', ['pointer']);
    this._fopen = new NativeFunction(api.findExport('fopen'), 'pointer', ['pointer', 'pointer']);
    this._popen = new NativeFunction(api.findExport('popen'), 'pointer', ['pointer', 'pointer']);

    this.allocateRw = function(size) {
        var pt = Memory.alloc(size);
        Memory.protect(pt, size, 'rw-');
        return pt;
    };

    this.fopen = function(filePath, perm) {
        var file_path_ptr = Memory.allocUtf8String(filePath);
        var p = Memory.allocUtf8String(perm);
        return this._fopen(file_path_ptr, p);
    };

    this.popen = function(filePath, perm) {
        var file_path_ptr = Memory.allocUtf8String(filePath);
        var p = Memory.allocUtf8String(perm);
        return this._popen(file_path_ptr, p);
    };

    this.readStringFromFile = function(filePath) {
        var fp = this.fopen(filePath, 'r');
        var ret = this.readStringFromFp(fp);
        this.fclose(fp);
        return ret;
    };

    this.readStringFromFp = function(fp) {
        var ret = "";
        if (fp !== null) {
            var buf = this.allocateRw(1024);
            while (ptr(this.fgets(buf, 1024, fp)) > ptr(0)) {
                ret += Memory.readUtf8String(buf);
            }
            return ret;
        }
        return ret;
    };

    this.writeStringToFile = function(filePath, content, append) {
        // use frida api
        if (typeof append === 'undefined') {
            append = false;
        }
        var f = new File(filePath, (append ? 'wa' : 'w'));
        f.write(content);
        f.flush();
        f.close();
    };
}

function DwarfKernel() {
    this.initialized = false;
    this.execve = new NativeFunction(Module.findExportByName('libc.so', 'execve'), 'int', ['pointer', 'pointer', 'pointer']);
    this.exec_kdwarf = Memory.allocUtf8String("kdwarf");

    this.data_buffer = null;
    this.root_pids = [];

    this.ftrace = null;

    function Ftrace(kernel) {
        this.PATH_AVAILABLE_EVENTS = "/sys/kernel/debug/tracing/available_events";
        this.PATH_AVAILABLE_FILTER_FUNCTIONS = "/sys/kernel/debug/tracing/available_filter_functions";
        this.PATH_CURRENT_TRACER = "/sys/kernel/debug/tracing/current_tracer";
        this.PATH_ENABLED = "/proc/sys/kernel/ftrace_enabled";
        this.PATH_OPTIONS = "/sys/kernel/debug/tracing/trace_options";
        this.PATH_SET_EVENTS_PID = "/sys/kernel/debug/tracing/set_event_pid";
        this.PATH_SET_EVENTS = "/sys/kernel/debug/tracing/set_event";
        this.PATH_SET_FILTERS = "/sys/kernel/debug/tracing/set_ftrace_filter";
        this.PATH_SET_FILTERS_NOTRACE = "/sys/kernel/debug/tracing/set_ftrace_notrace";
        this.PATH_SET_FTRACE_PID = "/sys/kernel/debug/tracing/set_ftrace_pid";
        this.PATH_TRACE = "/sys/kernel/debug/tracing/trace";
        this.PATH_TRACERS = "/sys/kernel/debug/tracing/available_tracers";
        this.PATH_TRACING_ON = "/sys/kernel/debug/tracing/tracing_on";

        this.kernel = kernel;

        this.availableEvents = function() {
            return fs.readStringFromFile(this.PATH_AVAILABLE_EVENTS);
        };

        this.availableFunctions = function() {
            return fs.readStringFromFile(this.PATH_AVAILABLE_FILTER_FUNCTIONS);
        };

        this.enabled = function() {
            return fs.readStringFromFile(this.PATH_ENABLED).substring(0, 1) === "1";
        };

        this.events = function() {
            return fs.readStringFromFile(this.PATH_SET_EVENTS);
        };

        this.filters = function() {
            return fs.readStringFromFile(this.PATH_SET_FILTERS);
        };

        this.options = function(asList) {
            if (typeof asList !== 'boolean') {
                asList = false;
            }
            var available_options = fs.readStringFromFile(this.PATH_OPTIONS).split('\n');
            if (asList) {
                return available_options;
            }
            var options = {};
            for (var opt in available_options) {
                var enabled = !available_options[opt].startsWith('no');
                options[available_options[opt].substring(enabled ? 0 : 2)] = enabled;
            }
            return options;
        };

        this.readTrace = function() {
            var f = fs.fopen(kernel.ftrace.PATH_TRACE, 'r');
            var buf = fs.allocateRw(Process.pointerSize);
            var len = fs.allocateRw(Process.pointerSize);
            var read;
            var lines = "";
            while ((read = fs.getline(buf, len, f)) !== -1) {
                lines += Memory.readUtf8String(Memory.readPointer(buf));
            }
            fs.fclose(f);
            return lines;
        };

        this.readTraceAsync = function() {
            var f = fs.fopen(kernel.ftrace.PATH_TRACE, 'r');
            var buf = fs.allocateRw(Process.pointerSize);
            var len = fs.allocateRw(Process.pointerSize);
            var read;
            while ((read = fs.getline(buf, len, f)) !== -1) {
                send("ftrace:::" + Memory.readUtf8String(Memory.readPointer(buf)));
            }
            fs.fclose(f);
        };

        this.setCurrentTracer = function(tracer) {
            var err = this.root();
            if (err > 0) {
                return err;
            }

            fs.writeStringToFile(this.PATH_CURRENT_TRACER, tracer);
        };

        this.setEvents = function(events) {
            var err = this.root();
            if (err > 0) {
                return err;
            }

            fs.writeStringToFile(this.PATH_SET_EVENTS, events);
        };

        this.setFilters = function(filters) {
            var err = this.root();
            if (err > 0) {
                return err;
            }

            fs.writeStringToFile(this.PATH_SET_FILTERS, filters);

            // Always disable tracing for nanosleep. Not sure it's really necessary to see nanosleeps but,
            // I can't figure out any good logic at the moment to prevent the spamage of nanosleeps which come from
            // dwarf breakpoint -> frida api -> thread.sleep()
            fs.writeStringToFile(this.PATH_SET_FILTERS_NOTRACE, '*nanosleep');
        };

        this.setOption = function(option, enabled) {
            var err = this.root();
            if (err > 0) {
                return err;
            }

            if (typeof enabled === 'undefined') {
                fs.writeStringToFile(this.PATH_OPTIONS, option);
            } else {
                fs.writeStringToFile(this.PATH_OPTIONS, (enabled ? '' : 'no') + option);
            }
        };

        this.setPid = function(pid) {
            var err = this.root();
            if (err > 0) {
                return err;
            }

            if (typeof pid !== 'string') {
                pid = pid + '';
            }

            fs.writeStringToFile(this.PATH_SET_EVENTS_PID, pid);
            fs.writeStringToFile(this.PATH_SET_FTRACE_PID, pid);
        };

        this.setTracing = function(tracing) {
            var err = this.root();
            if (err > 0) {
                return err;
            }

            if (typeof tracing !== 'boolean') {
                tracing = tracing === "1";
            }

            fs.writeStringToFile(this.PATH_TRACING_ON, tracing ? "1" : "0");
        };

        this.tracers = function() {
            return fs.readStringFromFile(this.PATH_TRACERS);
        };

        this.traceOwnPid = function() {
            this.setPid(Process.id);
        };

        this.tracing = function () {
            return fs.readStringFromFile(this.PATH_TRACING_ON).substring(0, 1) === "1";
        };
    }

    this._cmd = function(opt) {
        if (!this.initialized) {
            return 1;
        }
        opt = Memory.allocUtf8String(opt);
        this.execve(this.exec_kdwarf, opt, this.data_buffer);
        return 0;
    };

    this._init = function () {
        if (!this.available(true)) {
            return;
        }

        this.initialized = true;

        this.data_buffer = Memory.alloc(1024);
        Memory.protect(this.data_buffer, 1024, 'rw-');
        this.ftrace = new Ftrace(this);
    };

    this.available = function(internalCall) {
        if (typeof internalCall !== 'boolean') {
            internalCall = false;
        }
        var res;
        try {
            var opt = Memory.allocUtf8String("available");
            var availableResponseBuffer = Memory.alloc(256);
            Memory.protect(availableResponseBuffer, 256, 'rw-');
            this.execve(this.exec_kdwarf, opt, availableResponseBuffer);
            res = Memory.readUtf8String(availableResponseBuffer).split(" ");
            if (res[0] === '1') {
                if (internalCall) {
                    return true;
                }
                if (!this.initialized) {
                    this._init();
                }
                res.shift();
                return "available: " + res.join(' ');
            }
        } catch (e) {}
        if (internalCall) {
            return false;
        }
        return "not available";
    };

    this.enable = function() {
        if (this.available(true)) {
            send('enable_kernel:::')
        } else {
            console.log('dwarf module not loaded');
        }
    };

    this.lookupSymbol = function(what) {
        var err = this._cmd("kallsyms_lookup_name " + what);
        if (err) {
            console.log('lookupSymbol err: ' + err);
            return 0;
        }
        return Memory.readPointer(this.data_buffer);
    };

    this.root = function() {
        if (this.root_pids.indexOf(Process.getCurrentThreadId()) < 0) {
            var err = this._rootCall();
            if (err) {
                return err;
            }
        }
        return 0;
    };

    this._rootCall = function() {
        var err = this._cmd('loveme');
        if (err) {
            return err;
        }
        this.root_pids.push(Process.getCurrentThreadId());
        return 0;
    }
}

function JavaHelper() {
    this.available = Java.available;
    this._traced_classes = [];
    this._tracing = false;

    this.getApplicationContext = function() {
        if (!this.available) {
            return;
        }

        var ActivityThread = Java.use('android.app.ActivityThread');
        var Context = Java.use('android.content.Context');

        var context = Java.cast(ActivityThread.currentApplication().getApplicationContext(), Context);

        ActivityThread.$dispose();
        Context.$dispose();

        return context;
    };

    this.hook = function(className, method, implementation, restore) {
        Java.perform(function () {
            var handler;
            try {
                handler = Java.use(className);
            } catch (err) {
                return;
            }

            if (typeof handler[method] === 'undefined') {
                return;
            }

            var overloadCount = handler[method].overloads.length;
            var classMethod = className + '.' + method;

            if (overloadCount > 0) {
                var hook;
                if (!restore) {
                    send('hook_java_callback:::' + classMethod);
                    hook = new Hook();
                    hook.javaClassMethod = classMethod;
                    hook.javaOverloads = [];
                    getDwarf().hooks[classMethod] = hook;
                }

                for (var i = 0; i < overloadCount; i++) {
                    var impl = null;
                    if (!restore) {
                        var mArgs = handler[method].overloads[i].argumentTypes;
                        hook.javaOverloads[mArgs.length] = mArgs;
                        impl = javaHelper.hookImplementation(className, method, hook, implementation);
                    }
                    handler[method].overloads[i].implementation = impl;
                }
            }

            handler.$dispose();
        });
    };

    this.hookImplementation = function(className, method, hook, implementation) {
        return function () {
            var classMethod = className + '.' + method;
            var args = arguments;
            var types = hook.javaOverloads[args.length];
            var newArgs = {};
            for (var i=0;i<args.length;i++) {
                var value = '';
                if (args[i] === null || typeof args[i] === 'undefined') {
                    value = 'null';
                } else {
                    if (typeof args[i] === 'object') {
                        value = JSON.stringify(args[i]);
                        if (types[i]['className'] === '[B') {
                            value += ' (' + Java.use('java.lang.String').$new(args[i]) + ")";
                        }
                    } else {
                        value = args[i].toString();
                    }
                }
                newArgs[i] = {
                    arg: value,
                    name: types[i]['name'],
                    handle: args[i],
                    className: types[i]['className'],
                }
            }

            // check if clazz is traced
            if (javaHelper._traced_classes.indexOf(classMethod) >= 0) {
                // call trace implementation
                javaHelper.traceImplementation(classMethod).apply(this, arguments);
            }

            var result = 0;
            if (typeof implementation === 'function') {
                result = implementation.call(this, args);
            }
            if (result === 0) {
                getDwarf()._onHook(REASON_HOOK, classMethod, newArgs, hook, this);
            }
            return this[method].apply(this, args);
        };
    };

    this.startTrace = function(classes) {
        if (!this.available || this._tracing) {
            return false;
        }

        this._tracing = true;
        this._traced_classes = classes;

        Java.perform(function() {
            classes.forEach(function(className) {
                try {
                    var clazz = Java.use(className);

                    // check if classMethod is hooked. If so, tracing is handled in the hook callback
                    var classMethod = className + '.$init';
                    if (typeof getDwarf().hooks[classMethod] === 'undefined') {
                        var overloadCount = clazz["$init"].overloads.length;
                        if (overloadCount > 0) {
                            for (var i = 0; i < overloadCount; i++) {
                                clazz["$init"].overloads[i].implementation = javaHelper.traceImplementation(className, '$init');
                            }
                        }
                    }

                    var methods = clazz.class.getDeclaredMethods();
                    var parsedMethods = [];
                    methods.forEach(function(method) {
                        parsedMethods.push(method.toString().replace(className + ".",
                            "TOKEN").match(/\sTOKEN(.*)\(/)[1]);
                    });
                    methods = getDwarf().uniqueBy(parsedMethods, JSON.stringify);
                    methods.forEach(function(method) {
                        // same as ctor, check if method is hooked
                        // check if classMethod is hooked. If so, tracing is handled in the hook callback
                        var classMethod = className + '.' + method;
                        if (typeof getDwarf().hooks[classMethod] === 'undefined') {
                            var overloadCount = clazz[method].overloads.length;
                            if (overloadCount > 0) {
                                for (var i = 0; i < overloadCount; i++) {
                                    clazz[method].overloads[i].implementation = javaHelper.traceImplementation(className, method);
                                }
                            }
                        }
                    });

                    clazz.$dispose();
                } catch (e) {
                    _log(e);
                }
            });
        });
        return true;
    };

    this.stopTrace = function() {
        if (!this.available || !this._tracing) {
            return false;
        }

        this._tracing = false;
        Java.perform(function () {
        });
        return true;
    };

    this.traceImplementation = function(className, method) {
        return function() {
            var classMethod = className + '.' + method;
            send('java_trace:::enter:::' + classMethod + ':::' + JSON.stringify(arguments));
            var ret = this[method].apply(this, arguments);
            var traceRet = ret;
            if (typeof traceRet === 'object') {
                traceRet = JSON.stringify(ret);
            } else if (typeof traceRet === 'undefined') {
                traceRet = "";
            }
            send('java_trace:::leave:::' + classMethod + ':::' + traceRet);
            return ret;
        }
    }
}

function MemoryWatcher(address, perm) {
    this.address = address;
    this.original_permissions = perm;

    this.watch = function() {
        var perm = '---';
        if (this.original_permissions.indexOf('x') >= 0) {
            perm = '--x';
        }
        Memory.protect(this.address, 1, perm);
    };

    this.restore = function () {
        Memory.protect(this.address, 1, this.original_permissions)
    };
}

rpc.exports = {
    api: function(tid, api_funct, args) {
        if (typeof args === 'undefined' || args === null) {
            args = [];
        }

        if (Object.keys(getDwarf().hook_contexts).length > 0) {
            var hc = getDwarf().hook_contexts[tid];
            if (typeof hc !== 'undefined') {
                hc.next_api = [api_funct, args];
                while (hc.next_api_result === 'dwarf_handler') {
                    Thread.sleep(1 / 100);
                }
                var ret = hc.next_api_result;
                hc.next_api_result = 'dwarf_handler';
                return ret;
            }
        }

        return api[api_funct].apply(this, args)
    },
};

_log = console.log;
console.log = function(what) {
    if (what instanceof ArrayBuffer) {
        what = hexdump(what)
    } else if (what instanceof Object) {
        what = JSON.stringify(what, null, 2);
    }
    api.log(what);
};

var wrappedInterceptor = Interceptor;
var InterceptorWrapper = function() {
    this.attach = function (pt, logic) {
        try {
            var hook = new Hook();
            hook.nativePtr = ptr(pt);

            if (typeof logic === 'function') {
                hook.interceptor = wrappedInterceptor.attach(hook.nativePtr, function (args) {
                    var result = logic.call(this, args);
                    if (result >= 0) {
                        getDwarf()._onHook(REASON_HOOK, hook.nativePtr, this.context, hook, null);
                    }
                });
            } else if (typeof logic === 'object') {
                hook.interceptor = wrappedInterceptor.attach(hook.nativePtr, {
                    onEnter: function (args) {
                        var result = 0;
                        if (typeof logic['onEnter'] !== 'undefined') {
                            result = logic['onEnter'].call(this, args);
                        }
                        if (result >= 0) {
                            getDwarf()._onHook(REASON_HOOK, hook.nativePtr, this.context, hook, null);
                        }
                    },
                    onLeave: function (retval) {
                        if (typeof logic['onLeave'] !== 'undefined') {
                            logic['onLeave'].call(this, retval);
                        }
                    }
                });
            } else {
                hook.interceptor = wrappedInterceptor.attach(hook.nativePtr, function(args) {
                    getDwarf()._onHook(REASON_HOOK, hook.nativePtr, this.context, hook, null);
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

var wrappedThread = Thread;
var ThreadWrapper = function() {
    this.pthread_create = new NativeFunction(Module.findExportByName(libc, 'pthread_create'),
        'int', ['pointer', 'pointer', 'pointer', 'pointer']);
    this.handler = null;
    this.handler_fn = null;

    this._init = function() {
        this.handler = Memory.alloc(Process.pointerSize);
        Memory.protect(this.handler, Process.pointerSize, 'rwx');
        if (Process.arch === 'arm64') {
            Memory.writeByteArray(this.handler, [0xE1, 0x03, 0x01, 0xAA, 0xC0, 0x03, 0x5F, 0xD6]);
        }
        wrappedInterceptor.replace(this.handler, new NativeCallback(function() {
            if (Thread.handler_fn !== null) {
                return Thread.handler_fn.apply(this);
            }
            return 0;
        }, 'int', []));
    };

    this.backtrace = function(context, backtracer) {
        return wrappedThread.backtrace(context, backtracer);
    };

    this.new = function(fn) {
        if (typeof fn !== 'function') {
            return 1;
        }
        var pthread_t = Memory.alloc(Process.pointerSize);
        Memory.protect(pthread_t, Process.pointerSize, 'rwx');
        Thread.handler_fn = fn;
        return this.pthread_create(pthread_t, ptr(0), Thread.handler, ptr(0));
    };

    this.sleep = function(delay) {
        wrappedThread.sleep(delay);
    };

    this._init();
};
Thread = new ThreadWrapper();

/**
 Short hands api.
 Most of those are thought to handle ui/target data exchange
 **/
api = new DwarfApi();
fs = new DwarfFs();
kernel = new DwarfKernel();

getDwarf().start();
getDwarf()._sendInfos(REASON_SET_INITIAL_CONTEXT, null, null);