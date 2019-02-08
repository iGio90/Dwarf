---
layout: default
title: fs
parent: Api
nav_order: 3
---

# fs
{: .no_toc }


fs class exposes functions from wrapped libc api, such as popen etc. and allows file manipulation.

## Table of contents
{: .no_toc .text-delta }

* TOC
{:toc}

---

#### fclose
#### fgets
#### fileno
#### fopen
#### fputs
#### getline
#### popen
#### pclose

```javascript
// real example from base library
// both accept path and perm as string in params
var f = fs.fopen(kernel.ftrace.PATH_TRACE, 'r');
var buf = fs.allocateRw(Process.pointerSize);
var len = fs.allocateRw(Process.pointerSize);
var read;
var lines = "";
while ((read = fs.getline(buf, len, f)) !== -1) {
    lines += Memory.readUtf8String(Memory.readPointer(buf));
}
fs.fclose(f);
```

---

## allocateRw
```javascript
var buf = fs.allocateRw(1024);
```

> allocate memory in the heap with read and write perm

---

## readStringFromFile
```javascript
var available_options = fs.readStringFromFile(this.PATH_OPTIONS).split('\n');
```

> read the whole content of a file path and return it's content as string

---

## readStringFromFp

> read the whole content of a file pointer (from fopen i.e) and return it's content as string

---

## writeStringToFile
```javascript
fs.writeStringToFile("/path/to/file", "content");
```

> write the content of arg1 in the path specified in arg0. Eventually, you can pass a third param boolean to append the content to an existing file

