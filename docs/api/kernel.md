---
layout: default
title: kernel
parent: Api
nav_order: 4
---

# kernel
{: .no_toc }


kernel class speaks with [dwarf kernel module](https://github.com/iGio90/Dwarf-LKM) to provide some useful stuffs from the kernel space.

## Table of contents
{: .no_toc .text-delta }

* TOC
{:toc}

---

## available
```javascript
kernel.available();
```

> return a string indicating if the process can speak with dwarf kernel module

---

## enable
```javascript
kernel.enable();
```

> enable kernel features on dwarf UI if the module is loaded 

---

## lookupSymbol
```javascript
kernel.lookupSymbol('sys_call_table');
```

> return the pointer of the symbol specified in arg0

---

## root
```javascript
kernel.root();
```

> elevate the calling process to root
