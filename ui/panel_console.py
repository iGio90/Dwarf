"""
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
"""
from PyQt5.QtWidgets import QTabWidget, QSplitter

from ui.widget_console import DwarfConsoleWidget


class ConsolePanel(QSplitter):
    def __init__(self, parent=None, *__args):
        super().__init__(*__args)
        self.parent = parent

        self.qtabs = QTabWidget()

        self.js_console = DwarfConsoleWidget(parent, input_placeholder='$>', function_box=True)
        self.js_console.onCommandExecute.connect(self.js_callback)

        #self.r2_console = DwarfConsoleWidget(parent, input_placeholder='r2')
        #self.r2_console.onCommandExecute.connect(self.r2_callback)

        self.py_console = DwarfConsoleWidget(parent, input_placeholder='>>>')
        self.py_console.onCommandExecute.connect(self.py_callback)

        self.emu_console = DwarfConsoleWidget(parent, has_input=False)

        self.qtabs.addTab(self.js_console, 'javascript')
        self.qtabs.addTab(self.py_console, 'python')
        #self.addTab(self.r2_console, 'r2')
        self.qtabs.addTab(self.emu_console, 'emulator')

        self.events = DwarfConsoleWidget(parent, has_input=False)

        self.addWidget(self.qtabs)
        self.addWidget(self.events)

    def clear(self):
        self.js_console.clear()
        self.py_console.clear()

    def get_js_console(self):
        return self.js_console

    def get_py_console(self):
        return self.py_console

    def get_r2_console(self):
        return self.r2_console

    def get_emu_console(self):
        return self.emu_console

    def get_events_console(self):
        return self.events

    def show_console_tab(self, tab_name):
        tab_name = tab_name.join(tab_name.split()).lower()
        if tab_name == 'javascript':
            self.qtabs.setCurrentIndex(0)
        elif tab_name == 'python':
            self.qtabs.setCurrentIndex(1)
        #elif tab_name == 'r2':
        #    self.setCurrentIndex(2)
        elif tab_name == 'emulator':
            self.qtabs.setCurrentIndex(2)
        else:
            self.qtabs.setCurrentIndex(0)

    def js_callback(self, text):
        # the output in the logs is handled in dwarf_api
        self.parent.dwarf.dwarf_api('evaluate', text)

    def r2_callback(self, cmd):
        response = self.parent.dwarf.r2.api(cmd)
        self.r2_console.log(response)

    def py_callback(self, text):
        try:
            self.py_console.log(exec(text))
        except Exception as e:
            self.py_console.log(str(e))
