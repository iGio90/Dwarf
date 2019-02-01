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
    def __init__(self, app):
        super().__init__()
        self.app = app

        self.js_console = QConsoleWidget(self.app, self.js_callback, input_placeholder='$>', function_box=True)
        self.py_console = QConsoleWidget(self.app, self.py_callback, input_placeholder='>>>')

        self.addTab(self.js_console, 'javascript')
        self.addTab(self.py_console, 'python')

    def clear(self):
        self.js_console.clear()
        self.py_console.clear()

    def get_js_console(self):
        return self.js_console

    def get_py_console(self):
        return self.py_console

    def js_callback(self, text):
        # the output in the logs is handled in dwarf_api
        self.app.dwarf_api('evaluate', text)

    def py_callback(self, text):
        self.py_console.log(eval(text))
