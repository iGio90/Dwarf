---
layout: default
title: Interceptor
parent: Api
nav_order: 5
---

# Interceptor
{: .no_toc }


all functions from [frida Interceptor](https://www.frida.re/docs/javascript-api#Interceptor) are available.

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## attach
```javascript
Interceptor.attach(targetPtr, function() {
    // execute logic here
    // dwarf will break the thread and output the content in the ui unless an integer < 0 is returned
    // the same can be applied to onLoads hooks

    api.setData('hit ' + n_hits, 'content');
    n_hits += 1;

    // don't break or sleep
    return -1;
});
```
