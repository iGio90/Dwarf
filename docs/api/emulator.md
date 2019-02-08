---
layout: default
title: emulator
parent: Api
nav_order: 2
---

# emulator
{: .no_toc }


emulator javascript api are built to expose a way to interact with [unicorn emulator](https://www.unicorn-engine.org/).


## Table of contents
{: .no_toc .text-delta }

* TOC
{:toc}

---

## clean
```javascript
emulator.clean();
```

> clean the ui, unmap all regions and start from the initial context

---

## setup
```javascript
emulator.setup(Process.getCurrentThreadId());
```

> setup the emulator with the context hooked at specified thread id

---

## start
```javascript
var stopEmulationAt = 0xdeadbeef;
emulator.start(stopEmulationAt);
```

> start the emulation until exception or ``stopEmulationAt`` address is hit

---

## step
```javascript
emulator.step();
```

> step to the next instruction

---

## stop
```javascript
emulator.stop();
```

> stop the emulation
