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
from PyQt5.QtWidgets import QTabWidget

from ui.widget_console import QConsoleWidget


class ConsolePanel(QTabWidget):
    def __init__(self, parent=None):
        super(ConsolePanel, self).__init__(parent=parent)
        self.parent = parent

        self.js_console = QConsoleWidget(parent, input_placeholder='$>', function_box=True)
        self.js_console.onCommandExecute.connect(self.js_callback)

        self.py_console = QConsoleWidget(parent, input_placeholder='>>>')
        self.py_console.onCommandExecute.connect(self.py_callback)

        self.emu_console = QConsoleWidget(parent, has_input=False)

        self.addTab(self.js_console, 'javascript')
        self.addTab(self.py_console, 'python')
        self.addTab(self.emu_console, 'emulator')

    def clear(self):
        self.js_console.clear()
        self.py_console.clear()

    def get_js_console(self):
        return self.js_console

    def get_py_console(self):
        return self.py_console

    def get_emu_console(self):
        return self.emu_console

    def show_console_tab(self, tab_name):
        tab_name = tab_name.join(tab_name.split()).lower()
        if tab_name == 'javascript':
            self.setCurrentIndex(0)
        elif tab_name == 'python':
            self.setCurrentIndex(1)
        elif tab_name == 'emulator':
            self.setCurrentIndex(2)
        else:
            self.setCurrentIndex(0)

    def js_callback(self, text):
        # the output in the logs is handled in dwarf_api
        self.parent.dwarf.dwarf_api('evaluate', text)

    def py_callback(self, text):
        self.py_console.log(eval(text))
