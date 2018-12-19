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

### Must have todo list:
* Java hooks
* Hooks logic
* ~~Conditional hooks~~
* Unicorn integration
* ~~ASM view on memory panel~~
* ASM view options (i.e switch to thumb on arm32)
* A way to highlight pointers and data in memory panel (i failed hard. like 10 seconds for 1024 bytes of data is far from a fuckyeah!)
* 'Show as data' on memory panel
* export / import session 
* tools and options 