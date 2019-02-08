---
layout: default
title: Installation
nav_order: 3
---

# Installation

Dwarf vs your first target
{: .fs-6 .fw-300 }

---

### Pre requisites
A frida server running anywhere.

### Setup and run

```bash
git clone https://github.com/iGio90/Dwarf

pip3 install -r requirements.txt


# start the ui allowing process pick/spawn
python3 dwarf.py

# start the ui straight vs the target
python3 dwarf.py -p com.my.target -sp

```

### Optionally

You can install keystone-engine to enable assembler:


Windows

[x86](https://github.com/keystone-engine/keystone/releases/download/0.9.1/keystone-0.9.1-python-win32.msi)
[x64](https://github.com/keystone-engine/keystone/releases/download/0.9.1/keystone-0.9.1-python-win64.msi)

OSX / Unix

```bash
pip3 install keystone-engine
```



