# Dwarf

A debugger for reverse engineers, crackers and security analyst.
Or you can call it damn, why are raspberries so fluffy or yet, duck warriors are rich as fuck. Whatever you like!
Built on top of pyqt5, frida and some terrible code.


![DWARF](https://i.ibb.co/bKYm5Sr/Screenshot-from-2019-07-17-23-35-00.png)
![DWARFWHITE](https://i.ibb.co/hHHHc8m/Screenshot-from-2019-07-17-23-35-28.png)

### Something you can do with Dwarf
* breakpoints
* watchpoints without hardware support
* breaks module loading cycle, java classes
* set breaks conditions and custom logics
* inject code on each breakpointed thread
* exchange data with your target and display it in UI
* digging through memory, disassembly and jvm fields/functions
* backtrace both native and java
* takes your whole frida agent in script editor, convert hooks to breakpoints etc
* plugins to enhance features and ui
* everything can be done through scripting to build custom debugging logic

### Pre requisites
A frida server running anywhere.

#### Android Session:
  + make sure you can use 'adb' command in console or [Read here](https://www.xda-developers.com/adb-fastboot-any-directory-windows-linux/)
  + root on the device/emulator is required!
  + make sure frida is in /system/bin|xbin with a+x permissions or eventually use Dwarf to automatically install latest frida server 

### Setup and run

```
git clone https://github.com/iGio90/Dwarf

cd Dwarf

pip3 install -r requirements.txt

python3 dwarf.py
```


dex2jar tools (required for baksmali/decompiling)
```
Guide: https://sourceforge.net/p/dex2jar/wiki/UserGuide/
Files: https://github.com/pxb1988/dex2jar/releases

On Windows add d2j folder to %PATH% and change:
'java -Xms512m -Xmx1024m -cp "%CP%" %*'
in d2j_invoke.bat to
'java -Xms512m -Xmx4096m -cp "%CP%" %*'
```

### Extend
You can extend Dwarf with plugins. [Checkout how to get it done!](PLUGINS.md)

### Settings
You can change in .dwarf
```
"dwarf_ui_hexedit_bpl": 32 (default: 16) - Bytes per line in hexview
"dwarf_ui_hexstyle": "upper", "lower" (default: "upper") - overall hexstyle 0xabcdef or 0xABCDEF (note: click on the "Offset (X)" in hexview to change)
"dwarf_ui_font_size": 12 (default: 12) - (note: hexview/disasm use other font wait for settingsdlg or change lib/utils.py get_os_monospace_font())
```
+ ToolMenu

   ```
   "tools": [{"name": "Calculator", "cmd": "calc"}, {"name": "Terminal", "cmd": "sh"}]
   ```
   *to place an separator you can use `{"name": "sep"}`*

----

```
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
```
