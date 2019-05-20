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

/**
 * those are meant to be exposed
 */
var DEBUG = false;

var api = null;
var dwarf = null;
var emulator = null;
var fs = null;
var kernel = null;
var javaHelper = null;

var REASON_SET_INITIAL_CONTEXT = 0;
var REASON_HOOK = 0;
var REASON_WATCHER = 1;

//const
var MEMORY_ACCESS_READ = 1;
var MEMORY_ACCESS_WRITE = 2;
var MEMORY_ACCESS_EXECUTE = 4;
var MEMORY_WATCH_SINGLESHOT = 8;

function isDefined(value) {
    return (value !== undefined) && (value !== null) && (typeof value !== 'undefined');
}

function isNumber(value) {
    if (isDefined(value)) {
        return (typeof value === "number" && (isNaN(value) === false));
    }
    return false;
}

function isString(value) {
    if (isDefined(value)) {
        return (typeof value === "string");
    }
    return false;
}

function getDwarf() {
    if (dwarf === null) {
        dwarf = new Dwarf();
    }

    return dwarf;
}

// js needleds
Date.prototype.getTwoDigitHour = function() {
    return (this.getHours() < 10) ? '0' + this.getHours() : this.getHours();
};

Date.prototype.getTwoDigitMinute = function() {
    return (this.getMinutes() < 10) ? '0' + this.getMinutes() : this.getMinutes();
};

Date.prototype.getTwoDigitSecond = function() {
    return (this.getSeconds() < 10) ? '0' + this.getSeconds() : this.getSeconds();
};

Date.prototype.getHourMinuteSecond = function() {
    return this.getTwoDigitHour() + ':' + this.getTwoDigitMinute() + ':' + this.getTwoDigitSecond();
};

function Dwarf() {
    this.proc_resumed = false;
    this.hook_contexts = {};
    this.hooks = {};
    this.nativeOnLoads = {};
    this.javaOnLoads = {};
    this.java_handlers = {};
    this.memory_watchers = {};
    this.memory_addresses = [];

    // setup pc register
    this.procedure_call_register = null;
    if (Process.arch === 'arm' || Process.arch === 'arm64') {
        this.procedure_call_register = 'pc'
    } else if (Process.arch === 'ia32') {
        this.procedure_call_register = 'eip';
    } else if (Process.arch === 'x64') {
        this.procedure_call_register = 'rip';
    }

    // Watchers on Windoof
    this._onMemoryAccess = function (details) {
        var tid = Process.getCurrentThreadId();
        var watcher = null;
        var operation = details.operation; // 'read' - 'write' - 'execute'
        var fromPtr = details.from;
        var address = details.address;

        // watchers
        if (Object.keys(getDwarf().memory_watchers).length > 0) {
            watcher = getDwarf().memory_watchers[address];
            if (typeof watcher !== 'undefined') {
                var returnval = {'memory': {'operation': operation, 'address': address}};
                if ((watcher.flags & MEMORY_ACCESS_READ) && (operation === 'read')) {
                    MemoryAccessMonitor.disable();
                    loggedSend('watcher:::' + JSON.stringify(returnval) + ':::' + tid);
                } else if ((watcher.flags & MEMORY_ACCESS_WRITE) && (operation === 'write')) {
                    MemoryAccessMonitor.disable();
                    loggedSend('watcher:::' + JSON.stringify(returnval) + ':::' + tid);
                } else if ((watcher.flags & MEMORY_ACCESS_EXECUTE) && (operation === 'execute')) {
                    MemoryAccessMonitor.disable();
                    loggedSend('watcher:::' + JSON.stringify(returnval) + ':::' + tid);
                } else {
                    watcher = null;
                }
            } else {
                watcher = null;
            }
        }
        if (watcher !== null) {
            var hook = new Hook();
            hook.nativePtr = fromPtr;
            hook.interceptor = Interceptor.attach(fromPtr, function () {
                getDwarf()._onHook(REASON_WATCHER, hook.nativePtr, this.context, hook, null);
                if (!(watcher.flags & MEMORY_WATCH_SINGLESHOT)) {
                    MemoryAccessMonitor.enable(this.memory_addresses, {onAccess: this._onMemoryAccess});
                }
                hook.interceptor.detach();
            });
        }
        return watcher !== null;
    };

    this._handleException = function (exception) {
        if (DEBUG) {
            _log('[' + Process.getCurrentThreadId() + '] exception handler: ' + JSON.stringify(exception));
        }
        var tid = Process.getCurrentThreadId();
        var watcher = null;

        if (Process.platform === 'windows') {
            // stalker.follow gives illegal-instruction on windows
            // same as https://github.com/frida/frida-gum/issues/195
            // after illegal-instruction it throws access-violation read
            // return handled=true to keep dwarf running or it will be terminated
            // process is terminated
            /*
                Error: illegal instruction
                Error: access violation accessing 0x5d6102a
                Error: access violation accessing 0x70 - repeated ~20times
            */

            if (exception['type'] === 'illegal-instruction') {
                return true;
            }

            if (exception['type'] === 'access-violation') {
                return true;
            }
        }

        // watchers
        if (Object.keys(getDwarf().memory_watchers).length > 0) {
            // make sure it's access violation
            if (exception['type'] === 'access-violation') {
                watcher = getDwarf().memory_watchers[exception['memory']['address']];
                if (typeof watcher !== 'undefined') {
                    if (typeof exception['memory']['operation'] !== 'undefined') {
                        var operation = exception['memory']['operation'];
                        if ((watcher.flags & MEMORY_ACCESS_READ) && (operation === 'read')) {
                            watcher.restore();
                            loggedSend('watcher:::' + JSON.stringify(exception) + ':::' + tid);
                        } else if ((watcher.flags & MEMORY_ACCESS_WRITE) && (operation === 'write')) {
                            watcher.restore();
                            loggedSend('watcher:::' + JSON.stringify(exception) + ':::' + tid);
                        } else if ((watcher.flags & MEMORY_ACCESS_EXECUTE) && (operation === 'execute')) {
                            watcher.restore();
                            loggedSend('watcher:::' + JSON.stringify(exception) + ':::' + tid);
                        } else {
                            watcher = null;
                        }
                    } else {
                        watcher.restore();
                        loggedSend('watcher:::' + JSON.stringify(exception) + ':::' + tid);
                    }
                } else {
                    watcher = null;
                }
            }
        }

        if (watcher !== null) {
            getDwarf()._onHook(REASON_WATCHER, hook.nativePtr, this.context, null, null);
            if (!(watcher.flags & MEMORY_WATCH_SINGLESHOT)) {
                watcher.watch();
            }
        }
        return watcher !== null;
    };

    this._ba2hex = function (b) {
        var uint8arr = new Uint8Array(b);
        if (!uint8arr) {
            return '';
        }
        var hexStr = '';
        for (var i = 0; i < uint8arr.length; i++) {
            var hex = (uint8arr[i] & 0xff).toString(16);
            hex = (hex.length === 1) ? '0' + hex : hex;
            hexStr += hex;
        }
        return hexStr;
    };

    this._hex2a = function (hex) {
        for (var bytes = [], c = 0; c < hex.length; c += 2)
            bytes.push(parseInt(hex.substr(c, 2), 16));
        return bytes;
    };

    this._dethumbify = function (pt) {
        pt = ptr(pt);
        if (Process.arch.indexOf('arm') !== -1) {
            if (parseInt(pt) & 1 === 1) {
                pt = pt.sub(1);
            }
        }
        return pt;
    };

    this.uniqueBy = function (array, key) {
        var seen = {};
        return array.filter(function (item) {
            var k = key(item);
            return seen.hasOwnProperty(k) ? false : (seen[k] = true);
        });
    };

    this._loopApi = function (that) {
        if (DEBUG) {
            _log('[' + Process.getCurrentThreadId() + '] looping api');
        }
        var op = recv('' + Process.getCurrentThreadId(), function(payload) {});
        op.wait();

        var hook_context = getDwarf().hook_contexts[Process.getCurrentThreadId()];

        if (typeof hook_context !== 'undefined') {
            while (hook_context.next_api === null) {
                Thread.sleep(0.01);
            }

            if (DEBUG) {
                _log('[' + Process.getCurrentThreadId() + '] executing ' + hook_context.next_api[0]);
            }

            hook_context.next_api_result = api[hook_context.next_api[0]].apply(that, hook_context.next_api[1]);

            if (hook_context.next_api[0] !== 'release') {
                // invalidate
                hook_context.next_api = null;

                getDwarf()._loopApi(that);
            }
        }
    };

    this._onHook = function (reason, p, context, hook, java_handle) {
        if (DEBUG) {
            _log('[' + Process.getCurrentThreadId() + '] onHook ' + p + ' - reason: ' + reason);
        }

        var that = {};
        var shouldSleep = true;

        that['context'] = context;
        that['handle'] = java_handle;

        if (hook !== null) {
            if (hook.condition !== null) {
                try {
                    //todo: check here 'this' is dwarf() and has no context prop
                    this.context = that['context'];
                    var res = eval(hook.condition);
                    if (res !== null && typeof (res) === 'boolean') {
                        if (!res) {
                            return null;
                        }
                    }
                } catch (e) {
                    _log_err('_onHook', e);
                }
            }

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
                    _log_err('_onHook', e);
                }
            }
        }

        if (DEBUG) {
            _log('[' + Process.getCurrentThreadId() + '] onHook ' + p + ' - pre-sleep: ' + shouldSleep);
        }

        if (shouldSleep) {
            if (DEBUG) {
                _log('[' + Process.getCurrentThreadId() + '] onHook ' + p + ' - dispatching context info');
            }
            this._sendInfos(reason, p, context);

            if (DEBUG) {
                _log('[' + Process.getCurrentThreadId() + '] onHook ' + p + ' - creating dwarf context');
            }

            var hc = new HookContext(Process.getCurrentThreadId());
            hc.context = context;
            hc.java_handle = java_handle;
            this.hook_contexts[hc.tid] = hc;
            that['hook_context'] = hc;

            if (DEBUG) {
                _log('[' + hc.tid + '] onHook ' + p + ' - sleeping context. goodnight!');
            }

            this._loopApi(that);

            if (DEBUG) {
                _log('[' + hc.tid + '] HookContext has been released');
            }

            delete this.hook_contexts[hc.tid];
        }
        //todo: check here 'this' is dwarf() and has no context prop
        return this.context;
    };

    this._sendInfos = function (reason, p, ctx) {
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
            if (DEBUG) {
                _log('[' + tid + '] sendInfos - preparing infos for valid context');
            }

            data['context'] = ctx;
            var pc = this.procedure_call_register;
            if (typeof ctx[pc] !== 'undefined') {
                var symb;
                try {
                    symb = DebugSymbol.fromAddress(ctx[pc]);
                } catch (e) {
                    _log_err('_sendInfos', e);
                }
                if (symb === null || typeof symb === 'undefined') {
                    symb = {};
                }

                if (DEBUG) {
                    _log('[' + tid + '] sendInfos - preparing native backtrace');
                }

                bt = {'bt': api.nativeBacktrace(ctx), 'type': 'native'};
                data['ptr'] = p;
                data['is_java'] = false;
                data['backtrace'] = bt;

                var newCtx = {};
                if (DEBUG) {
                    _log('[' + tid + '] sendInfos - preparing context registers');
                }
                for (var reg in ctx) {
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
                    if (reg === pc) {
                        newCtx[reg]['symbol'] = symb;
                        try {
                            var inst = Instruction.parse(p);
                            newCtx[reg]['instruction'] = {
                                'size': inst.size,
                                'groups': inst.groups,
                                'thumb': inst.groups.indexOf('thumb') >= 0 ||
                                    inst.groups.indexOf('thumb2') >= 0
                            };
                        } catch (e) {
                            _log_err('_sendInfos', e);
                        }
                    }
                    data['context'] = newCtx;
                }
            } else {
                // java hook
                data['is_java'] = true;
                data['ptr'] = p;
                if (DEBUG) {
                    _log('[' + tid + '] sendInfos - preparing java backtrace');
                }
                bt = {'bt': api.javaBacktrace(), 'type': 'java'};
                data['backtrace'] = bt;
            }
        } else if (ctx === null) {
            data['arch'] = Process.arch;
            data['platform'] = Process.platform;
            data['java'] = Java.available;
            data['modules'] = Process.enumerateModulesSync();
            data['pid'] = Process.id;
            data['pointerSize'] = Process.pointerSize;
            data['ranges'] = Process.enumerateRangesSync('---');
        }

        if (DEBUG) {
            _log('[' + tid + '] sendInfos - dispatching infos');
        }

        loggedSend('set_context:::' + JSON.stringify(data));
    };

    this.start = function () {
        Process.setExceptionHandler(getDwarf()._handleException);

        // windows native onload code
        if (Process.platform === 'windows') {
            var symbols = Module.enumerateExportsSync('kernel32.dll');
            var loadliba_ptr = 0;
            var loadlibexa_ptr = 0;
            var loadlibw_ptr = 0;
            var loadlibexw_ptr = 0;

            for (var symbol in symbols) {
                if (symbols[symbol].name.indexOf('LoadLibraryA') >= 0) {
                    loadliba_ptr = symbols[symbol].address;
                } else if (symbols[symbol].name.indexOf('LoadLibraryW') >= 0) {
                    loadlibw_ptr = symbols[symbol].address;
                } else if (symbols[symbol].name.indexOf('LoadLibraryExA') >= 0) {
                    loadlibexa_ptr = symbols[symbol].address;
                } else if (symbols[symbol].name.indexOf('LoadLibraryExW') >= 0) {
                    loadlibexw_ptr = symbols[symbol].address;
                }

                if ((loadliba_ptr > 0) && (loadlibw_ptr > 0) && (loadlibexa_ptr > 0) && (loadlibexw_ptr > 0)) {
                    break;
                }
            }
            if ((loadliba_ptr > 0) && (loadlibw_ptr > 0) && (loadlibexa_ptr > 0) && (loadlibexw_ptr > 0)) {
                Interceptor.attach(loadliba_ptr, function (args) {
                    try {
                        var w = Memory.readAnsiString(args[0]);
                        for (var s in getDwarf().nativeOnLoads) {
                            if (w.indexOf(s) >= 0) {
                                var hook = getDwarf().nativeOnLoads[s];
                                loggedSend("native_onload_callback:::" + hook.module + ':::' + 0 + ':::' + Process.getCurrentThreadId());
                                getDwarf()._onHook(REASON_HOOK, this.context.pc, this.context, hook, null);
                            }
                        }
                    } catch (e) {
                        _log_err('Dwarf.start', e);
                    }
                });
                Interceptor.attach(loadlibexa_ptr, function (args) {
                    try {
                        var w = Memory.readAnsiString(args[0]);
                        for (var s in getDwarf().nativeOnLoads) {
                            if (w.indexOf(s) >= 0) {
                                var hook = getDwarf().nativeOnLoads[s];
                                loggedSend("native_onload_callback:::" + hook.module + ':::' + 0 + ':::' + Process.getCurrentThreadId());
                                getDwarf()._onHook(REASON_HOOK, this.context.pc, this.context, hook, null);
                            }
                        }
                    } catch (e) {
                        _log_err('Dwarf.start', e);
                    }
                });
                Interceptor.attach(loadlibw_ptr, function (args) {
                    try {
                        var w = Memory.readUtf16String(args[0]);
                        for (var s in getDwarf().nativeOnLoads) {
                            if (w.indexOf(s) >= 0) {
                                var hook = getDwarf().nativeOnLoads[s];
                                loggedSend("native_onload_callback:::" + hook.module + ':::' + 0 + ':::' + Process.getCurrentThreadId());
                                getDwarf()._onHook(REASON_HOOK, this.context.pc, this.context, hook, null);
                            }
                        }
                    } catch (e) {
                        _log_err('Dwarf.start', e);
                    }
                });
                Interceptor.attach(loadlibexw_ptr, function (args) {
                    try {
                        var w = Memory.readUtf16String(args[0]);
                        for (var s in getDwarf().nativeOnLoads) {
                            if (w.indexOf(s) >= 0) {
                                var hook = getDwarf().nativeOnLoads[s];
                                loggedSend("native_onload_callback:::" + hook.module + ':::' + 0 + ':::' + Process.getCurrentThreadId());
                                getDwarf()._onHook(REASON_HOOK, this.context.pc, this.context, hook, null);
                            }
                        }
                    } catch (e) {
                        _log_err('Dwarf.start', e);
                    }
                });
            }
        } else if (Java.available) {
            // create the java helper instance
            javaHelper = new JavaHelper();

            // android native onload code
            var symb = Module.enumerateSymbolsSync(Process.arch.indexOf('64') >= 0 ? 'linker64' : "linker");
            var phdr_tgds_ptr = 0;
            var do_dlopen_ptr = 0;

            for (var sym in symb) {
                if (symb[sym].name.indexOf("phdr_table_get_dynamic_section") >= 0) {
                    phdr_tgds_ptr = symb[sym].address;
                } else if (symb[sym].name.indexOf('do_dlopen') >= 0) {
                    do_dlopen_ptr = symb[sym].address;
                }
                if (phdr_tgds_ptr > 0 && do_dlopen_ptr > 0) {
                    break;
                }
            }

            if (phdr_tgds_ptr > 0 && do_dlopen_ptr > 0) {
                var hook = null;

                Interceptor.attach(phdr_tgds_ptr, function (args) {
                    if (hook !== null) {
                        loggedSend("native_onload_callback:::" + hook.module + ':::' + args[2] + ':::' + Process.getCurrentThreadId());
                        getDwarf()._onHook(REASON_HOOK, this.context.pc, this.context, hook, null);
                        hook = null;
                    }
                });

                Interceptor.attach(do_dlopen_ptr, function (args) {
                    try {
                        var w = Memory.readCString(args[0]);
                        loggedSend('native_onload_module_loading:::' + Process.getCurrentThreadId() + ':::' + w);
                        for (var s in getDwarf().nativeOnLoads) {
                            if (w.indexOf(s) >= 0) {
                                hook = getDwarf().nativeOnLoads[s];
                            }
                        }
                    } catch (e) {
                        _log_err('Dwarf.start', e);
                    }
                });
            }

            // attach to commonInit for init debugging
            javaHelper.hook('com.android.internal.os.RuntimeInit',
                'commonInit', true, null, false, true);

            // attach to classLoader to notify for new loaded class
            // todo
        }
    };
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
        Interceptor.detachAll();
        api.release();
        // wait all contexts to be released
    };

    this._internalMemoryScan = function(start, size, pattern) {
        if (size > 4096) {
            // scan in chunks of 4096
            var _start = parseInt(start);
            var end = _start + size;
            var result = [];
            var _break = false;
            while (true) {
                var s = 4096;
                if (_start + s > end) {
                    s = end - _start;
                    _break = true;
                }
                result = result.concat(Memory.scanSync(start, s, pattern));
                if (_break || result.length >= 100) {
                    break;
                }
                start = start.add(size);
                _start += s;
            }
            return result;
        } else {
            return Memory.scanSync(start, size, pattern);
        }
    };

    this.addWatcher = function(pt, flags) {
        pt = ptr(pt);
        // default '--?'
        if (typeof flags === 'undefined') {
            flags = (MEMORY_ACCESS_READ | MEMORY_ACCESS_WRITE);
        }

        if (Process.platform === 'windows') {
            if (typeof getDwarf().memory_watchers[pt] === 'undefined') {
                var range = Process.findRangeByAddress(pt);
                if (range === null) {
                    return;
                }
                getDwarf().memory_watchers[pt] = new MemoryWatcher(pt, range.protection, flags);
                getDwarf().memory_addresses.push({ 'base': pt, 'size': 1 });
                loggedSend('watcher_added:::' + pt + ':::' + flags);
            }
            MemoryAccessMonitor.enable(getDwarf().memory_addresses, { onAccess: getDwarf()._onMemoryAccess });
            return;
        }

        if (typeof getDwarf().memory_watchers[pt] === 'undefined') {
            var range = Process.findRangeByAddress(pt);
            if (range === null) {
                return;
            }
            getDwarf().memory_watchers[pt] = new MemoryWatcher(pt, range.protection, flags);
            loggedSend('watcher_added:::' + pt + ':::' + flags);
        }
        getDwarf().memory_watchers[pt].watch();
    };

    this.deleteHook = function(key) {
        if (typeof key === 'number') {
            key = getDwarf()._dethumbify(key);
        } else if (typeof key === 'string' && key.startsWith('0x')) {
            key = getDwarf()._dethumbify(key);
        }

        var hook = getDwarf().hooks[key];

        if (typeof hook === 'undefined') {
            if (typeof getDwarf().nativeOnLoads[key] !== 'undefined') {
                loggedSend('hook_deleted:::native_onload:::' + key);
                delete getDwarf().nativeOnLoads[key];
            } else {
                _log('undefined hook with key: ' + key);
            }
            return;
        }

        if (hook.interceptor !== null) {
            hook.interceptor.detach();
            delete getDwarf().hooks[key];
            loggedSend('hook_deleted:::native:::' + key);
        } else if (hook.javaClassMethod !== null) {
            api.hookJavaConstructor(hook.javaClassMethod, null, true);
            api.hookJavaMethod(hook.javaClassMethod, null, true);
            delete getDwarf().hooks[key];
            loggedSend('hook_deleted:::java:::' + key);
        }
    };

    this.enumerateExports = function(module) {
        return JSON.stringify(Module.enumerateExportsSync(module));
    };

    this.enumerateImports = function(module) {
        try {
        return JSON.stringify(Module.enumerateImportsSync(module));
        } catch(e) {
            _log_err('enumerateImports', e);
        }
    };

    this.enumerateJavaClasses = function() {
        Java.performNow(function() {
            loggedSend('enumerate_java_classes_start:::');
            try {
                Java.enumerateLoadedClasses({
                    onMatch: function(className) {
                        send('enumerate_java_classes_match:::' + className);
                    },
                    onComplete: function() {
                        send('enumerate_java_classes_complete:::');
                    }
                });
            } catch(e) {
                _log_err('enumerateJavaClasses', e);
                loggedSend('enumerate_java_classes_complete:::');
            }
        });
    };

    this.enumerateJavaMethods = function(className) {
        if (Java.available) {
            Java.performNow(function () {
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
                loggedSend('enumerate_java_methods_complete:::' + className + ':::' +
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
            var Interceptor = DwarfInterceptor;
            var Thread = new ThreadWrapper();
            var res = eval(w);
            if (!nolog && typeof res !== 'undefined') {
                console.log(res);
            }
            return res;
        } catch (e) {
            _log_err('evaluate', e);
            return '';
        }
    };

    this.evaluateFunction = function(w) {
        try {
            var fn = new Function('Interceptor', 'Thread', w);
            return fn.apply(this, [DwarfInterceptor, new ThreadWrapper()]);
        } catch (e) {
            _log_err('evaluateFunction', e);
            return '';
        }
    };

    this.evaluatePtr = function(w) {
        try {
            return ptr(eval(w));
        } catch (e) {
            _log_err('evaluatePtr', e);
            return ptr(0);
        }
    };

    this.findExport = function(name, module) {
        if (typeof module === 'undefined') {
            module = null;
        }
        return Module.findExportByName(null, name);
    };

    this.findModule = function(name) {
        return Process.findModuleByName(name);
    };

    this.findSymbol = function(pattern) {
        return DebugSymbol.findFunctionsMatching(pattern);
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
                        return [0, s];
                    }
                } catch (e) {
                    _log_err('getAddressTs-1', e);
                }

                // valid pointer
                return [1, w];
            } else {
                try {
                    var s = Memory.readUtf8String(ptr(p));
                    if (s.length > 1) {
                        // valid string
                        return [0,  s];
                    }
                } catch (e) {
                    _log_err('getAddressTs-2', e);
                }
            }
        } catch (e) {
            _log_err('getAddressTs-3', e);
            return [-1, ''];
        }

        // int
        return [2, w];
    };

    this.getInstruction = function(address) {
        try {
            var instruction = Instruction.parse(ptr(address));
            return JSON.stringify({
                'string': instruction.toString()
            });
        } catch (e) {
            _log_err('getInstruction', e);
        }
        return null;
    };

    this.getModules = function() {
        return Process.enumerateModulesSync();
    };

    this.getRange = function(pt) {
        try {
            pt = ptr(pt);
            if (pt === null || parseInt(pt) === 0) {
                return [];
            }
            var ret = Process.findRangeByAddress(pt);
            if (ret == null) {
                return [];
            }
            return ret;
        } catch (e) {
            _log_err('getRange', e);
            return [];
        }
    };

    this.getRanges = function() {
        return Process.enumerateRangesSync('---');
    };

    this.getSymbolByAddress = function(pt) {
        try {
            pt = ptr(pt);
            return DebugSymbol.fromAddress(pt);
        } catch (e) {
            _log_err('getSymbolByAddress', e);
            return {};
        }
    };

    this.javaBacktrace = function () {
        return Java.use("android.util.Log")
            .getStackTraceString(Java.use("java.lang.Exception").$new());
    };

    this.hookAllJavaMethods = function(className) {
        if (!Java.available) {
            return false;
        }

        Java.performNow(function () {
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
    };

    this.hookJavaConstructor = function(className, implementation, restore) {
        if (!Java.available) {
            return;
        }
        restore = typeof restore === 'undefined' ? false : restore;
        javaHelper.hook(className, '$init', true, implementation, restore, false);
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
        javaHelper.hook(targetClass, targetMethod, true, implementation, restore, false);
    };

    this.hookNative = function(what, logic) {
        DwarfInterceptor.attach(what, logic);
    };

    this.hookNativeOnLoad = function(m, logic) {
        if (getDwarf().nativeOnLoads[m] === null || typeof(getDwarf().nativeOnLoads[m]) === 'undefined') {
            var hook = new Hook();
            hook.module = m;
            if (typeof logic !== 'undefined') {
                hook.logic = logic;
            }
            getDwarf().nativeOnLoads[m] = hook;
            loggedSend('hook_native_onload_callback:::' + m);
        }
    };

    this.isAddressWatched = function(pt) {
        var watcher = getDwarf().memory_watchers[ptr(pt)];
        return typeof watcher !== 'undefined';
    };

    this.injectBlob = function(name, blob) {
        // arm syscall memfd_create
        var sys_num = 385;
        if (Process.arch === 'ia32') {
            sys_num = 356;
        } else if (Process.arch === 'x64') {
            sys_num = 319;
        }

        var syscall_ptr = api.findExport('syscall');
        var write_ptr = api.findExport('write');
        var dlopen_ptr = api.findExport('dlopen');

        if (syscall_ptr !== null && !syscall_ptr.isNull()) {
            var syscall = new NativeFunction(syscall_ptr, 'int', ['int', 'pointer', 'int']);
            if (write_ptr !== null && !write_ptr.isNull()) {
                var write = new NativeFunction(write_ptr, 'int', ['int', 'pointer', 'int']);
                if (dlopen_ptr !== null && !dlopen_ptr.isNull()) {
                    var dlopen = new NativeFunction(dlopen_ptr, 'int', ['pointer', 'int']);

                    var m = fs.allocateRw(128);
                    Memory.writeUtf8String(m, name);
                    var fd = syscall(sys_num, m, 0);
                    if (fd > 0) {
                        blob = getDwarf()._hex2a(blob);
                        var blob_space = Memory.alloc(blob.length);
                        Memory.protect(blob_space, blob.length, 'rwx');
                        Memory.writeByteArray(blob_space, blob);
                        write(fd, blob_space, blob.length);
                        Memory.writeUtf8String(m, '/proc/' + Process.id + '/fd/' + fd);
                        return dlopen(m, 1);
                    } else {
                        return -4;
                    }
                } else {
                    return -3;
                }
            } else {
                return -2;
            }
        } else {
            return -1;
        }
    };

    this.isValidPointer = function(pt) {
        try {
            var r = Process.findRangeByAddress(ptr(pt));
            return r !== null && typeof r !== 'undefined';
        } catch (e) {
            _log_err('isValidPointer', e);
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
                    handle = this['hook_context']['java_handle'];
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
                            _log_err('javaExplorer', e + ' | ' + handle['$handle']);
                            return null;
                        }
                    } else {
                        try {
                            handle = Java.cast(ptr(handle), cl);
                        } catch (e) {
                            _log_err('javaExplorer', e + ' | ' + handle);
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
            if (handle === null || typeof handle === 'undefined') {
                console.log('Explorer handle null');
                return {};
            }
            var ol;
            try {
                ol = Object.getOwnPropertyNames(handle.__proto__);
            } catch (e) {
                _log_err('javaExplorer', e);
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
                } catch (e) {
                    _log_err('javaExplorer', e);
                }
            }
            return ret;
        }
    };

    this.log = function(what) {
        loggedSend('log:::' + what);
    };

    this.nativeBacktrace = function(ctx) {
        return Thread.backtrace(ctx, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress);
    };

    this.memoryScan = function(start, size, pattern) {
        var result = [];
        try {
            result = api._internalMemoryScan(ptr(start), size, pattern);
        } catch (e) {
            _log_err('memoryScan', e);
        }
        loggedSend('memoryscan_result:::' + JSON.stringify(result));
    };

    this.memoryScanList = function(ranges, pattern) {
        ranges = JSON.parse(ranges);
        var result = [];
        for (var i=0;i<ranges.length;i++) {
            try {
                result = result.concat(api._internalMemoryScan(ptr(ranges[i]['start']), ranges[i]['size'], pattern));
            } catch (e) {
                _log_err('memoryScanList', e);
            }
            if (result.length >= 100) {
                break;
            }
        }
        loggedSend('memoryscan_result:::' + JSON.stringify(result));
    };

    this.isPrintable = function (char) {
        try {
            var isprint_ptr = api.findExport('isprint');
            if (isDefined(isprint_ptr)) {
                var isprint_fn = new NativeFunction(isprint_ptr, 'int', ['int']);
                if (isDefined(isprint_fn)) {
                    return isprint_fn(char);
                }
            }
            else {
                if ((char > 31) && (char < 127)) {
                    return true;
                }
            }
            return false;
        } catch (e) {
            _log_err('isPrintable', e);
            return false;
        }
    };

    this.readString = function (pt, l) {
        try {
            pt = ptr(pt);
            var fstring = "";
            var length = -1;
            if (isNumber(l)) {
                length = l;
            }
            var range = Process.findRangeByAddress(pt);
            if (!isDefined(range)) {
                return "";
            }
            if (isString(range.protection) && range.protection.indexOf('r') === -1) {
                //Access violation
                return "";
            }
            var _np = new NativePointer(pt);
            if (!isDefined(_np)) {
                return "";
            }
            if (Process.platform === 'windows') {
                fstring = _np.readAnsiString(length);
            }
            if (isString(fstring) && (fstring.length === 0)) {
                fstring = _np.readCString(length);
            }
            if (isString(fstring) && (fstring.length === 0)) {
                fstring = _np.readUtf8String(length);
            }
            if (isString(fstring) && fstring.length) {
                for (var i = 0; i < fstring.length; i++) {
                    if (!api.isPrintable(fstring.charCodeAt(i))) {
                        fstring = null;
                        break;
                    }
                }
            }
            if (isString(fstring) && fstring.length) {
                return fstring;
            }
            else {
                return "";
            }
        } catch (e) {
            _log_err('readString', e);
            return "";
        }
    };

    this.readBytes = function(pt, l) {
        try {
            pt = ptr(pt);
            var data = Memory.readByteArray(pt, l);
            return data;
        } catch (e) {
            _log_err('readBytes', e);
            return [];
        }
    };

    this.readPointer = function(pt) {
        try {
            return Memory.readPointer(ptr(pt));
        } catch (e) {
            _log_err('readPointer', e);
            return ptr(0x0)
        }
    };

    this.release = function(tid) {
        if (typeof tid === 'undefined' || tid < 1) {
            for (var t in getDwarf().hook_contexts) {
                tid = getDwarf().hook_contexts[t].tid;
                console.log('resuming := ' + tid);
                loggedSend('release:::' + tid)
            }
        } else {
            var hc = getDwarf().hook_contexts[tid];
            if (typeof hc !== 'undefined') {
                console.log('resuming := ' + hc.tid);
                loggedSend('release:::' + hc.tid)
            }
        }
    };

    this.resume = function() {
        if (!getDwarf().proc_resumed) {
            getDwarf().proc_resumed = true;
            console.log('Resuming process...');
            loggedSend('resume:::0');
        } else {
            console.log('Error: Process already resumed');
        }
    };

    this.releaseFromJs = function (tid) {
        send('release_js:::' + tid);
    };

    this.removeWatcher = function(pt) {
        pt = ptr(pt);
        var watcher = getDwarf().memory_watchers[pt];
        if (typeof watcher !== 'undefined') {
            watcher.restore();
            if(Process.platform === 'windows') {
                MemoryAccessMonitor.disable();
                getDwarf().memory_addresses = getDwarf().memory_addresses.filter(function(value, index, arr){
                    return parseInt(value.base, 16) != pt;
                });
            }
            delete getDwarf().memory_watchers[pt];
            loggedSend('watcher_removed:::' + pt);
            return true;
        }
        return false;
    };

    this.restart = function() {
        if (Java.available) {
            Java.performNow(function () {
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
            loggedSend('set_data:::' + key, data)
        } else {
            if (data.constructor.name === 'Object') {
                data = JSON.stringify(data,null,4);
            }
            loggedSend('set_data:::' + key + ':::' + data)
        }
    };

    this.setHookCondition = function(pt, w) {
        try {
            var hook = null;
            try {
                hook = getDwarf().hooks[getDwarf()._dethumbify(pt)];
            } catch (e) {
                _log_err('setHookCondition', e);
            }

            if (typeof hook === 'undefined' || hook === null) {
                hook = getDwarf().nativeOnLoads[pt];
            }

            hook.condition = w;
            return true;
        } catch (e) {
            _log_err('setHookCondition', e);
            return false;
        }
    };

    this.setHookLogic = function(pt, w) {
        try {
            var hook = null;
            try {
                hook = getDwarf().hooks[getDwarf()._dethumbify(pt)];
            } catch (e) {
                _log_err('setHookLogic', e);
            }

            if (typeof hook === 'undefined' || hook === null) {
                hook = getDwarf().nativeOnLoads[pt];
            }
            if (typeof hook === 'undefined' || hook === null) {
                return false;
            }
            if (w.startsWith('{')) {
                w = '(' + w + ')';
                w = eval(w);
            }
            hook.logic = w;
            return true;
        } catch (e) {
            _log_err('setHookLogic', e);
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
        try {
            Stalker.follow(this._traced_tid, {
                events: {
                    call: true,
                    ret: false,
                    exec: false,
                    block: false,
                    compile: false
                },

                onReceive: function(events) {
                    loggedSend('tracer:::' + Stalker.parse(events, {
                        annotate: true,
                        stringify: true
                    }));
                }
            });
        } catch(e) {
            _log_err('startNativeTracer', e);
        }

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
        loggedSend('update_modules:::' + Process.getCurrentThreadId() + ':::' +
            JSON.stringify(Process.enumerateModulesSync()))
    };

    this.updateRanges = function() {
        try {
            loggedSend('update_ranges:::' + Process.getCurrentThreadId() + ':::' +
                JSON.stringify(Process.enumerateRangesSync('---')))
        } catch (e) {
            _log_err('updateRanges', e);
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
            _log_err('writeBytes', e);
            return false;
        }
    };

    this.writeUtf8 = function(pt, str) {
        try {
            pt = ptr(pt);
            Memory.writeUtf8String(pt, str);
            return true;
        } catch (e) {
            _log_err('writeUtf8', e);
            return false;
        }
    }
}

function DwarfFs() {
    var p = api.findExport('fclose');
    if (p !== null && !p.isNull()) {
        this.fclose = new NativeFunction(p, 'int', ['pointer']);
    }
    p = api.findExport('fcntl');
    if (p !== null && !p.isNull()) {
        this.fcntl = new NativeFunction(p, 'int', ['int', 'int', 'int']);
    }
    p = api.findExport('fgets');
    if (p !== null && !p.isNull()) {
        this.fgets = new NativeFunction(p, 'int', ['pointer', 'int', 'pointer']);
    }
    p = api.findExport('fileno');
    if (p !== null && !p.isNull()) {
        this.fileno = new NativeFunction(p, 'int', ['pointer']);
    }
    p = api.findExport('fputs');
    if (p !== null && !p.isNull()) {
        this.fputs = new NativeFunction(p, 'int', ['pointer', 'pointer']);
    }
    p = api.findExport('getline');
    if (p !== null && !p.isNull()) {
        this.getline = new NativeFunction(p, 'int', ['pointer', 'pointer', 'pointer']);
    }
    p = api.findExport('pclose');
    if (p !== null && !p.isNull()) {
        this.pclose = new NativeFunction(p, 'int', ['pointer']);
    }
    p = api.findExport('fopen');
    if (p !== null && !p.isNull()) {
        this._fopen = new NativeFunction(p, 'pointer', ['pointer', 'pointer']);
    }
    p = api.findExport('popen');
    if (p !== null && !p.isNull()) {
        this._popen = new NativeFunction(p, 'pointer', ['pointer', 'pointer']);
    }

    this.allocateRw = function(size) {
        var pt = Memory.alloc(size);
        Memory.protect(pt, size, 'rw-');
        return pt;
    };

    this.allocateString = function(what) {
        return Memory.allocUtf8String(what);
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
    var p = Module.findExportByName(null, 'execve');
    if (p !== null && !p.isNull) {
        this.execve = new NativeFunction(p, 'int', ['pointer', 'pointer', 'pointer']);
        this.exec_kdwarf = Memory.allocUtf8String("kdwarf");

        this.data_buffer = null;
        this.root_pids = [];

        this.ftrace = null;
    }

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
                loggedSend("ftrace:::" + Memory.readUtf8String(Memory.readPointer(buf)));
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
        if (typeof kernel.execve === 'undefined') {
            if (internalCall) {
                return false;
            } else {
                return "not available";
            }
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
        } catch (e) {
            _log_err('DwarfKernel.available', e);
        }
        if (internalCall) {
            return false;
        }
        return "not available";
    };

    this.enable = function() {
        if (this.available(true)) {
            loggedSend('enable_kernel:::')
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

function Emulator() {
    this.clean = function() {
        loggedSend('emulator:::clean')
    };

    this.setup = function(tid) {
        if (typeof tid !== 'number') {
            tid = Process.getCurrentThreadId();
        }
        loggedSend('emulator:::setup:::' + tid);
    };

    this.start = function(until) {
        loggedSend('emulator:::start:::' + until)
    };

    this.step = function() {
        loggedSend('emulator:::start:::0')
    };

    this.stop = function() {
        loggedSend('emulator:::stop')
    };
}

function Hook() {
    this.internalHook = false;

    this.nativePtr = null;
    this.debugSymbols = null;

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

    this.hook = function(className, method, shouldBreak, implementation, restore, internal) {
        Java.performNow(function () {
            var handler = null;

            internal = internal || false;

            try {
                handler = Java.use(className);
            } catch (err) {
                try {
                    className = className + '.' + method;
                    method = '$init';
                    handler = Java.use(className);
                } catch (err) {}

                _log_err('JavaHelper.hook', err);
                if (handler === null) {
                    return;
                }
            }

            try {
                if (handler == null || typeof handler[method] === 'undefined') {
                    return;
                }
            } catch (e) {
                // catching here not supported overload error from frida
                _log_err('JavaHelper.hook', e);
                return;
            }

            var overloadCount = handler[method].overloads.length;
            var classMethod = className + '.' + method;

            if (overloadCount > 0) {
                var hook;
                if (!restore) {
                    if (!internal) {
                        loggedSend('hook_java_callback:::' + classMethod);
                    }
                    hook = new Hook();
                    hook.javaClassMethod = classMethod;
                    hook.javaOverloads = [];
                    hook.internalHook = internal;
                    getDwarf().hooks[classMethod] = hook;
                }

                for (var i = 0; i < overloadCount; i++) {
                    var impl = null;
                    if (!restore) {
                        var mArgs = handler[method].overloads[i].argumentTypes;
                        hook.javaOverloads[mArgs.length] = mArgs;
                        impl = javaHelper.hookImplementation(className, method, hook, shouldBreak, implementation);
                    }
                    handler[method].overloads[i].implementation = impl;
                }
            }

            handler.$dispose();
        });
    };

    this.hookImplementation = function(className, method, hook, shouldBreak, implementation) {
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

            if (typeof implementation === 'function') {
                var result = implementation.call(this, args);
            }
            if (shouldBreak) {
                getDwarf()._onHook(REASON_HOOK, classMethod, newArgs, hook, this);
            }
            if (typeof result === 'undefined') {
                return this[method].apply(this, args);
            } else {
                return result;
            }
        };
    };

    this.startTrace = function(classes) {
        if (!this.available || this._tracing) {
            return false;
        }

        this._tracing = true;
        this._traced_classes = classes;

        Java.performNow(function() {
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
                    _log_err('JavaHelper.startTrace', e);
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
        return true;
    };

    this.traceImplementation = function(className, method) {
        return function() {
            var classMethod = className + '.' + method;
            loggedSend('java_trace:::enter:::' + classMethod + ':::' + JSON.stringify(arguments));
            var ret = this[method].apply(this, arguments);
            var traceRet = ret;
            if (typeof traceRet === 'object') {
                traceRet = JSON.stringify(ret);
            } else if (typeof traceRet === 'undefined') {
                traceRet = "";
            }
            loggedSend('java_trace:::leave:::' + classMethod + ':::' + traceRet);
            return ret;
        }
    }
}

function MemoryWatcher(address, perm, flags) {
    this.address = address;
    this.debugSymbols = DebugSymbol.fromAddress(address);
    this.flags = flags;
    this.original_permissions = perm;
    var _this = this;

    this.watch = function() {
        var perm = '';
        if (_this.flags & MEMORY_ACCESS_READ) {
            perm += '-';
        } else {
            perm += _this.original_permissions[0];
        }
        if (_this.flags & MEMORY_ACCESS_WRITE) {
            perm += '-';
        } else {
            perm += _this.original_permissions[1];
        }
        if(_this.flags & MEMORY_ACCESS_EXECUTE) {
            perm += '-';
        } else {
            if (_this.original_permissions[2] === 'x') {
                perm += 'x';
            } else {
                perm += '-';
            }
        }
        Memory.protect(_this.address, 1, perm);
    };

    this.restore = function () {
        Memory.protect(_this.address, 1, _this.original_permissions)
    };
}

rpc.exports = {
    api: function(tid, api_funct, args) {
        if (DEBUG) {
            _log('[' + tid + '] RPC-API: ' + api_funct + ' | args: ' + args);
        }

        if (typeof args === 'undefined' || args === null) {
            args = [];
        }

        if (Object.keys(getDwarf().hook_contexts).length > 0) {
            var hc = getDwarf().hook_contexts[tid];
            if (typeof hc !== 'undefined') {

                // wait for other apis to return
                while (hc.next_api !== null) {
                    Thread.sleep(.5);
                }

                hc.next_api = [api_funct, args];
                if (DEBUG) {
                    _log('[' + tid + '] RPC-API: ' + api_funct + ' waiting for api result');
                }
                while (hc.next_api_result === 'dwarf_handler') {
                    Thread.sleep(0.01);
                }
                var ret = hc.next_api_result;
                if (DEBUG) {
                    _log('[' + tid + '] RPC-API: ' + api_funct + ' api result: ' + ret);
                }
                hc.next_api_result = 'dwarf_handler';
                return ret;
            }
        }

        return api[api_funct].apply(this, args)
    },
    debug: function(debug) {
        DEBUG = debug;
    },
    hooks: function() {
        return JSON.stringify(getDwarf().hooks);
    },
    nativeonloads: function() {
        return JSON.stringify(getDwarf().nativeOnLoads);
    },
    javaonloads: function() {
        return JSON.stringify(getDwarf().javaOnLoads);
    },
    watchers: function() {
        return JSON.stringify(getDwarf().memory_watchers);
    }
};

var __log = console.log;
console.log = function(what) {
    if (what instanceof ArrayBuffer) {
        what = hexdump(what)
    } else if (what instanceof Object) {
        what = JSON.stringify(what, null, 2);
    }
    api.log(what);
};
var _log = function(what) {
    var date = new Date();
    var now = date.getHourMinuteSecond();
    if (what instanceof ArrayBuffer) {
        what = hexdump(what)
    } else if (what instanceof Object) {
        what = JSON.stringify(what, null, 2);
    }
    __log(now + ' ' + what);
};
var _log_err = function(tag, err) {
    _log('[ERROR-' + tag + '] ' + err);
};

var wrappedInterceptor = Interceptor;
var InterceptorWrapper = function() {
    this.attach = function (pt, logic) {
        try {
            var hook;
            var dethumbedPtr;
            if (pt instanceof Hook) {
                hook = pt;
                dethumbedPtr = getDwarf()._dethumbify(hook.nativePtr);
                if (typeof logic === 'undefined' && hook.logic !== null) {
                    logic = hook.logic;
                }
            } else {
                dethumbedPtr = getDwarf()._dethumbify(ptr(pt));
                hook = getDwarf().hooks[dethumbedPtr];
                if (typeof hook === 'undefined') {
                    hook = new Hook();
                    hook.nativePtr = ptr(pt);
                    hook.debugSymbols = DebugSymbol.fromAddress(hook.nativePtr)
                } else {
                    pt = hook;
                }
                hook.logic = logic;
            }

            // we will send this for range class and avoid showing frida trampolines when dumping ranges
            var bytes = Memory.readByteArray(dethumbedPtr, Process.pointerSize * 2);

            if (typeof logic === 'function') {
                hook.interceptor = Interceptor.attach(hook.nativePtr, function(args) {
                    var result = hook.logic.call(this, args);
                    if (typeof result === 'undefined' || (typeof result === 'number' && result >= 0)) {
                        getDwarf()._onHook(REASON_HOOK, hook.nativePtr, this.context, hook, null);
                    }
                });
            } else if (typeof logic === 'object') {
                hook.interceptor = Interceptor.attach(hook.nativePtr, {
                    onEnter: function (args) {
                        var result = 0;

                        if (typeof logic['onEnter'] !== 'undefined') {
                            result = hook.logic['onEnter'].call(this, args);
                        }
                        if (typeof result === 'undefined' || (typeof result === 'number' && result >= 0)) {
                            getDwarf()._onHook(REASON_HOOK, hook.nativePtr, this.context, hook, null);
                        }
                    },
                    onLeave: function (retval) {
                        if (typeof logic['onLeave'] !== 'undefined') {
                            hook.logic['onLeave'].call(this, retval);
                        }
                    }
                });
            } else {
                hook.interceptor = Interceptor.attach(hook.nativePtr, function(args) {
                    getDwarf()._onHook(REASON_HOOK, hook.nativePtr, this.context, hook, null);
                });
            }

            var _logic = hook.logic;
            if (typeof _logic !== 'undefined') {
                if (_logic.constructor.name === 'Object') {
                    _logic = '{\n';
                    if (typeof hook.logic['onEnter'] !== 'undefined') {
                        _logic += '    onEnter: ' + hook.logic['onEnter'];
                    }
                    if (typeof hook.logic['onLeave'] !== 'undefined') {
                        if (_logic !== '') {
                            _logic += ',\n'
                        }
                        _logic += '    onLeave: ' + hook.logic['onLeave'] + '\n';
                    }
                    _logic += '}';
                }
            } else {
                logic = ''
            }

            if (!(pt instanceof Hook)) {
                try {
                    getDwarf().hooks[dethumbedPtr] = hook;
                    loggedSend('hook_native_callback:::' +
                        getDwarf()._dethumbify(hook.nativePtr) + ':::' +
                        getDwarf()._ba2hex(bytes) + ':::' +
                        _logic + ':::' + hook.condition
                    );
                } catch(e) {
                    _log_err('InterceptorWrapper.attach', e);
                    return false;
                }
            }
            return true;
        } catch (e) {
            _log_err('InterceptorWrapper.attach', e);
            return false;
        }
    };
    this._attach = function(pt, cb) {
        return Interceptor._attach(pt, cb);
    };
    this.detachAll = function() {
        for (var hook in getDwarf().hooks) {
            api.deleteHook(hook);
        }
        return Interceptor.detachAll();
    };
    this.flush = function() {
        return Interceptor.flush();
    };
    this._replace = function(pt, nc, ret, args) {
        return Interceptor._replace(pt, nc, ret, args);
    };
    this.replace = function(pt, nc, ret, args) {
        return Interceptor.replace(pt, nc, ret, args);
    };
    this.revert = function(target) {
        return Interceptor.revert(target);
    };
};
var DwarfInterceptor = new InterceptorWrapper();

var wrappedThread = Thread;
var ThreadWrapper = function() {
    // attempt to retrieve pthread_create
    var pthread_create_ptr = Module.findExportByName(null, 'pthread_create');
    if (pthread_create_ptr != null && !pthread_create_ptr.isNull()) {
        this.pthread_create = new NativeFunction(pthread_create_ptr,
            'int', ['pointer', 'pointer', 'pointer', 'pointer']);
        this.handler = null;
        this.handler_fn = null;
    }

    // called at the right moment from the loading chain
    this._init = function() {
        // check if pthread create has been declared
        if (typeof this.pthread_create !== 'undefined') {
            // allocate space for a fake handler which we intercept to run the callback
            this.handler = Memory.alloc(Process.pointerSize);
            // set permissions
            Memory.protect(this.handler, Process.pointerSize, 'rwx');
            if (Process.arch === 'arm64') {
                // arm64 require some fake code to get a trampoline from frida
                Memory.writeByteArray(this.handler, [0xE1, 0x03, 0x01, 0xAA, 0xC0, 0x03, 0x5F, 0xD6]);
            }
            // hook the fake handler
            Interceptor.replace(this.handler, new NativeCallback(function() {
                // null check for handler function
                if (Thread.handler_fn !== null) {
                    // invoke callback
                    var ret = Thread.handler_fn.apply(this);
                    // reset callback (unsafe asf... but we don't care)
                    Thread.handler_fn = null;
                    // return result
                    return ret;
                }
                return 0;
            }, 'int', []));
        }
    };

    this.backtrace = function(context, backtracer) {
        return wrappedThread.backtrace(context, backtracer);
    };

    this.new = function(fn) {
        // check if pthread_create is defined
        if (typeof Thread.pthread_create === 'undefined') {
            return 1;
        }

        // check if fn is a valid function
        if (typeof fn !== 'function') {
            return 2;
        }

        // alocate space for struct pthread_t
        var pthread_t = Memory.alloc(Process.pointerSize);
        // set necessary permissions
        Memory.protect(pthread_t, Process.pointerSize, 'rwx');
        // store the function into thread object
        Thread.handler_fn = fn;
        // spawn the thread
        return Thread.pthread_create(pthread_t, ptr(0), Thread.handler, ptr(0));
    };

    this.sleep = function(delay) {
        wrappedThread.sleep(delay);
    };

    this._init();
};

var loggedSend = function(w, p) {
    if (DEBUG) {
        _log('[' + Process.getCurrentThreadId() + '] sending data to py side | ' + w);
    }

    return send(w, p);
};

/**
 Short hands api.
 Most of those are thought to handle ui/target data exchange
 **/
api = new DwarfApi();
emulator = new Emulator();
fs = new DwarfFs();
kernel = new DwarfKernel();

getDwarf().start();
getDwarf()._sendInfos(REASON_SET_INITIAL_CONTEXT, null, null);