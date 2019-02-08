---
layout: default
title: api
parent: Api
nav_order: 1
---

# api
{: .no_toc }


api class is designed to expose mainly short hands wrappers of frida api, 
functions to exchange data with the ui and perform operations while scripting.

## Table of contents
{: .no_toc .text-delta }

* TOC
{:toc}

---

## addWatcher
```javascript
api.addWatcher(0xc4d8ff30);
```

> Add a memory watcher which will trigger dwarf ui and break the thread when a memory address got read or write

----

## deleteHook
```javascript
api.deleteHook(key);
```

> Javascript api to remove an hook by key. Could be a pointer if the hook is native, a module if it's OnLoad or a string pointer or a string java class method etc

----

## enumerateJavaClasses
```javascript
api.enumerateJavaClasses();
```

> Start enumeration of java classes async and send data to the ui

----

## enumerateJavaMethods
```javascript
api.enumerateJavaMethods();
```

> Start enumeration of java methods async and send data to the ui

----

## findExport
```javascript
api.findExport('target_function', 'target_module.so');
```

> shortcut of frida api Module.findExportByName with the advantage to accept only 1 argument. if module is not set, default will be 'libc' on android and 'libSystem.b.dylib' for ios

----

## getAddressTs
```javascript
api.getAddressTs(0xdb884dc2);
```

> Check the data pointed by a pointer. ptr is an integer or an hexadecimal numeric string "0x1000".

> return an array with 2 values. 
First one representing the type of the data:
0: string,
1: pointer,
2: int,
-1: error.
Second one is the data

----

## hookAllJavaMethods
```javascript
api.hookAllJavaMethods('com.android.targetClass');
```

> hook all the java methods of the given class

----

## hookJava
```javascript
api.hookJava('com.android.targetClass');
api.hookJava('com.android.targetClass.myMethod');
```

> a shortcut to hook either a java constructor or method (all overloads)

----

## hookNative
```javascript
// breakpoint on open
api.hookNative(api.findExport('open'));
```

> a shortcut to frida api Interceptor.attach() which pause the thread and let you debug through dwarf. Eventually, a logic (function()) can be added as second argument to perform additional stuffs and prevent the thread to be sleeped

----

## hookOnLoad
```javascript
// breakpoint on open
api.hookOnLoad('libtarget.so');
```

> hook a module before initialization. (works only on Android). Eventually, a logic (function()) can be added as second argument to perform additional stuffs and prevent the thread to be sleeped

----

## javaBacktrace
```javascript
api.javaBacktrace();
```

> A shortcut for java backtrace

----

## isAddressWatched
```javascript
api.isAddressWatched(0xd6c8fd9a);
```

> Return a boolean indicating if the address is currently watched

----

## nativeBacktrace
```javascript
api.nativeBacktrace();
```

----

## release
```javascript
api.release();
api.release(1274);
```

> Release a thread id and resume execution. (basically, unpause the thread after an hook is hit) Release all of them if no arg is specified

----

## removeWatcher
```javascript
api.removeWatcher(0xcfd4aab4);
```

> Remove memory watcher from the given pointer

----

## restart
```javascript
api.restart();
```

> Restart the application from main. This logic is only built for Android at the moment

----

## setData
```javascript
api.setData(key, value);
```

> An api suggested by a friend to send data straight to the UI. You can check an example usage [here](https://github.com/iGio90/Dwarf/wiki/Using-the-data-panel) 

----

## startNativeTracer
```javascript
api.startNativeTracer(4556);
```

> Start tracing the given thread id, return a boolean indicating if the tracer started. You can trace one thread at time

----

## stopNativeTracer
```javascript
api.stopNativeTracer();
```

> Stop tracing the previously traced thread id