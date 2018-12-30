# DWARF

A gui for mobile reverse engineers and crackers.
Or damn, what a reversed fluffy or yet, duck warriors are rich as fuck. Whatever you like!
Built on top of pyqt5, frida and some terrible code. 

![Dwarf](https://i.ibb.co/NYHB0g7/Schermata-2018-12-30-alle-08-59-06.png)

### Play with dwarf
[![IMAGE ALT TEXT HERE](https://img.youtube.com/vi/Bl7Aoe3UxgM/0.jpg)](https://www.youtube.com/watch?v=Bl7Aoe3UxgM)

---
For discussion and suggestions, please let's have a speak on [Slack](https://join.slack.com/t/resecret/shared_invite/enQtMzc1NTg4MzE3NjA1LTlkNzYxNTIwYTc2ZTYyOWY1MTQ1NzBiN2ZhYjQwYmY0ZmRhODQ0NDE3NmRmZjFiMmE1MDYwNWJlNDVjZDcwNGE)!

### Pre requisites
A rooted Android with frida server installed and running.

### Setup and run

```
git clone https://github.com/iGio90/Dwarf

pip3 install -r requirements.txt

python3 main.py
```

### Knowledge base

Once spawned - Dwarf attach to the onCreate method of the android Application class and sleep the process until release button is pushed.
(We could later figure out an earlier spot if needed)

A good time to begin adding hooks in the top left panel.
When you add an hook, an input dialog will pop. This input will be evaluated with frida api - aka - using frida api inside the input is possible (Module.findExportByName etc.)
You can double click on the thread id (if multiple hooks got hit on different threads) to switch context.
You can keep have fun with all the features you expect from a debugger.

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
