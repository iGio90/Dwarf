---
layout: default
title: Thread
parent: Api
nav_order: 6
---

# Thread
{: .no_toc }


all functions from [frida Thread](https://www.frida.re/docs/javascript-api#Thread) are available.

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## new
```javascript
Thread.new(function() {
    // do stuffs
});
```

> spawn a new thread using posix C api pthread_create
