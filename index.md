---
layout: default
title: Home
nav_order: 1
description: "Just the Docs is a responsive Jekyll theme with built-in search that is easily customizable and hosted on GitHub Pages."
permalink: /
---

# Dwarf debugger
{: .fs-9 }

Full featured multi arch/os debugger built on top of PyQt5 and frida
{: .fs-6 .fw-300 }

[Get started now]({{ site.baseurl }}{% link docs/installation.md %}){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 } [View it on GitHub](https://github.com/iGio90/Dwarf){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## What is Dwarf

As the title suggest, dwarf is a debugger, built on top of various frameworks and logics to simplify my life in reverse engineering tasks.
In the beginning, it was an experiment and a first approach to PyQt in the attempt to give an ui to [frida](http://frida.re).
It was mainly designed to work on Android but later, with a small effort, the support for iOS as been added with ease since they share the same arch.
Nowadays, mainly thanks to the community effort and the sure fact that open-source is the path (and of course to the power of [frida](http://frida.re),
Dwarf can debug on any operating system as a target and run on any desktop operating system (thanks to PyQt).

---

## Why you **shouldn't** use Dwarf.

1. In the "reverse engineering" scene there are a lot of context in which a debugger could be used.
All the features has been coded and tested on different scenarios and thanks to the community (and a lot of if else) it handle most of the cases, but not all of them.
You could meet issues, and probably you will have to patch some code.

2. if you are looking for something that gives you magic powers without the necessary environment, this is not the case and you should switch to another tool. 
Dwarf is coded also to give some space to work with an unrooted Android (in example), but most of the features would just not work.
Most of the effort has been spent into bringing compatibility for Windows, aka.. all paths bring to Rome, but linux is the best vehicle.

----

## Why you **should** give it a try:

1. because I'm sure you could find one of the [features](./features.html) very useful for the reason that takes you here.
2. it's open-source
3. it's built on top of the best technologies in terms of reverse engineering [frida](http://frida.re), [capstone](http://www.capstone-engine.org/), 
[keystone](http://www.keystone-engine.org/), [apktool](https://ibotpeaches.github.io/Apktool/), and so on
4. the guys behind the scenes are always up on [slack](https://join.slack.com/t/resecret/shared_invite/enQtMzc1NTg4MzE3NjA1LTlkNzYxNTIwYTc2ZTYyOWY1MTQ1NzBiN2ZhYjQwYmY0ZmRhODQ0NDE3NmRmZjFiMmE1MDYwNWJlNDVjZDcwNGE)
ready to discuss new stuffs to implement
5. because it kick asses