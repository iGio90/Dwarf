# Dwarf

[![PyPI pyversions](https://img.shields.io/pypi/pyversions/dwarf_debugger.svg)](https://pypi.python.org/pypi/dwarf_debugger/)
[![PyPI version shields.io](https://img.shields.io/pypi/v/dwarf_debugger.svg)](https://pypi.python.org/pypi/dwarf_debugger/)
[![GitHub license](https://img.shields.io/github/license/iGio90/Dwarf.svg)](https://github.com/iGio90/Dwarf/blob/master/LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/iGio90/Dwarf.svg)](https://GitHub.com/iGio90/Dwarf/issues/)

A debugger for reverse engineers, crackers and security analyst.
Or you can call it damn, why are raspberries so fluffy or yet, duck warriors are rich as fuck. Whatever you like!
Built on top of pyqt5, frida and some terrible code.

### Known Issues
+ JavaTraceView is distorted
+ JavaTraceView shows weakref/handle instead of value

We are working on Dwarf 2.0 release


### Installation
```
pip3 install dwarf-debugger
```
Development
```
pip3 install https://github.com/iGio90/Dwarf/archive/master.zip
```

## Usage

#### Debugging UI (attach wizard)

```
dwarf
```

#### Debugging UI (straightforward)
```
dwarf -t android com.facebook.katana
dwarf -t android 2145
dwarf -t ios 2145
dwarf -t local /usr/bin/cat /etc/shadow
```

#### Debugging UI (own agent)
```
dwarf -t android -s /path/to/agent.js com.facebook.katana
dwarf -t local -s /path/to/agent.js /usr/bin/cat /etc/shadow
```

#### Dwarf typings + injector
```
$ dwarf-creator
project path (/home/igio90/test):
> 
project name (test):
> 
Session type (local)
[*] L (local)
[*] A (android)
[*] I (iOS)
[*] R (remote)

append i to use dwarf-injector (ai | android inject)
> ai
target package (com.whatsapp)
> com.whatsapp

$ (./intelliJ || ./vsCode).open(/home/igio90/test)
    .echo('enjoy scripting with frida and dwarf api autocompletition and in-line doc')

$ ./dwarf if myOs == 'unix' else 'dwarf.bat'
```

#### Dwarf trace
```
dwarf-trace -t android --java java.io.File.$init com.facebook.katana

* Trying to spawn com.facebook.katana
* Dwarf attached to 19337
java.io.File $init
    /data  - java.io.File
    misc

java.io.File $init
    /data/misc  - java.io.File
    user

...
```

```
dwarf-trace -t android --native --native-registers x0,x1,sp open+0x32
dwarf-trace -t android --native --native-registers x0,x1,sp targetModule@0x1234
dwarf-trace -t android --native --native-registers x0,x1,sp 0xdc00d0d0
dwarf-trace -t android --native --native-registers x0,x1,sp popen
```

## DwarfCore (source of core.js)
Core for the Python version of dwarf
https://github.com/iGio90/DwarfCore/tree/core1

<p align="center">
  <br>
  <img src="dwarf_debugger/assets/dwarf.png">
  <br>
  <br>
  <br>
  <a href="https://igio90.github.io/Dwarf/" target="_blank">Javascript</a> |
  <a href="https://github.com/iGio90/Dwarf/blob/master/LICENSE">License</a> |
  <a href="https://www.patreon.com/securereturn" target="_blank">Become a patron</a> |
  <a href="https://join.slack.com/t/resecret/shared_invite/enQtMzc1NTg4MzE3NjA1LWZjY2YwMDA3OWZlZDg5Y2Y4NzRkYjE0ZjYzZGEwNDE2YmU0YTI0ZGJlZmNhODgzNDM1YzZmNWNlNGMwNDNhYTI" target="_blank">Slack</a>
  <br>
  <br>
</p>
