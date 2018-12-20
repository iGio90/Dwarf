# DWARF

Aka my wip gui for android reverse engineers and crackers.
Built on top of pyqt5 (compatible with all os's), frida and some terrible code. 

![Alt text](https://i.ibb.co/tPDRgmN/Schermata-2018-12-18-alle-18-35-02.png "Dwarf") 


### Pre requisites
A rooted Android with frida server installed and running.

### Setup and run

```
git clone https://github.com/iGio90/Dwarf

python3 main.py com.target.package -s
```

### WIP

More doc will follow when the 'must-have' to-do and better api are exposed.

For the moment, you can try to play around and right click on various panels.

For discussion and suggestions, please let's have a speak on [Slack](https://join.slack.com/t/resecret/shared_invite/enQtMzc1NTg4MzE3NjA1LTlkNzYxNTIwYTc2ZTYyOWY1MTQ1NzBiN2ZhYjQwYmY0ZmRhODQ0NDE3NmRmZjFiMmE1MDYwNWJlNDVjZDcwNGE)!

### Getting started

Once spawned - Dwarf attach to the onCreate method of the android Application class and sleep the process until release button is pushed.
A good time to begin adding hooks in the top left panel.
When you add an hook, an input dialog will pop. This input will be evaluated with frida api - aka - using frida api inside the input is possible (Module.findExportByName etc.)
You can double click on the thread id (if multiple hooks got hit on different threads) to switch context.

### todo
* 'Show as data' in memory panel
* Patch instructions on asm view
* Unicorn integration
* Single thread unsleep
* Debug Symbols list on x ranges
* Internal updates

```
Dwarf - Copyright (C) 2019 iGio90

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