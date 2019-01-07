"""
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
"""
import threading

from lib.adb import Adb
from lib.core import Dwarf
from ui.menu_bar import MenuBar

from PyQt5.QtWidgets import *

from ui.ui_session import SessionUi
from ui.ui_welcome import WelcomeUi


class AppWindow(QMainWindow):
    def __init__(self, dwarf_args, flags=None, *args, **kwargs):
        super().__init__(flags, *args, **kwargs)

        self.app = App(self)
        self.adb = Adb(self.app)

        self.dwarf = Dwarf(self)

        self.setWindowTitle("Dwarf")

        self.setCentralWidget(self.app)
        self.app.setup_ui()

        self.menu = MenuBar(self)
        if dwarf_args.package is not None:
            self.dwarf.spawn(dwarf_args.package, dwarf_args.script)

    def get_adb(self):
        return self.adb

    def get_app_instance(self):
        return self.app

    def on_context_info(self):
        self.get_menu().on_context_info()

    def get_dwarf(self):
        return self.dwarf

    def get_menu(self):
        return self.menu

    def on_script_destroyed(self):
        self.menu.on_script_destroyed()
        self.app.on_script_destroyed()

    def on_script_loaded(self):
        self.menu.on_script_loaded()
        self.app.on_script_loaded()


class App(QWidget):
    def __init__(self, app_window, flags=None, *args, **kwargs):
        super().__init__(flags, *args, **kwargs)

        self.app_window = app_window
        self.arch = ''
        self.pointer_size = 0

        self.box = QVBoxLayout()
        self.box.setContentsMargins(0, 0, 0, 0)

        self.welcome_ui = None
        self.session_ui = None

        self.contexts = []
        self.context_tid = 0

    def setup_ui(self):
        self.session_ui = SessionUi(self)
        self.welcome_ui = WelcomeUi(self)

        self.session_ui.hide()

        self.box.addWidget(self.welcome_ui)
        self.box.addWidget(self.session_ui)

        self.setLayout(self.box)

    def restart(self):
        self.dwarf_api('restart')
        self.resume()
        self.get_contexts_panel().setRowCount(0)

    def resume(self):
        self.get_contexts_panel().setRowCount(0)
        self.contexts.clear()
        self.get_registers_panel().setRowCount(0)
        self.get_backtrace_panel().setRowCount(0)
        self.dwarf_api('release')

    def clear(self):
        self.modules_panel.setRowCount(0)
        self.ranges_panel.setRowCount(0)
        self.session_ui.get_log_panel().clear()

    def set_modules(self, modules):
        self.session_ui.modules_panel.set_modules(modules)

    def set_ranges(self, ranges):
        self.session_ui.ranges_panel.set_ranges(ranges)

    def _apply_context(self, context):
        self.context_tid = context['tid']
        if 'modules' in context:
            self.set_modules(context['modules'])
        if 'ranges' in context:
            self.set_ranges(context['ranges'])
        if 'context' in context:
            is_java = context['is_java']
            self.get_registers_panel().set_context(context['ptr'], is_java, context['context'])
            if not is_java and 'pc' in context['context']:
                self.get_memory_panel().read_memory(context['context']['pc'])
        if 'backtrace' in context:
            self.get_backtrace_panel().set_backtrace(context['backtrace'])

    def apply_context(self, context):
        threading.Thread(target=self._apply_context, args=(context,)).start()

    def dwarf_api(self, api, args=None):
        return self.get_dwarf().dwarf_api(api, args)

    def get_adb(self):
        return self.app_window.get_adb()

    def get_asm_panel(self):
        return self.session_ui.asm_panel

    def get_arch(self):
        return self.arch

    def get_backtrace_panel(self):
        return self.session_ui.backtrace_panel

    def get_context_tid(self):
        return self.context_tid

    def get_contexts(self):
        return self.contexts

    def get_contexts_panel(self):
        return self.session_ui.contexts_panel

    def get_data_panel(self):
        return self.session_ui.data_panel

    def get_dwarf(self):
        return self.app_window.get_dwarf()

    def get_hooks_panel(self):
        return self.session_ui.hooks_panel

    def get_java_classes_panel(self):
        return self.session_ui.java_class_panel

    def get_log_panel(self):
        return self.session_ui.log_panel

    def get_memory_panel(self):
        return self.session_ui.memory_panel

    def get_modules_panel(self):
        return self.session_ui.modules_panel

    def get_pointer_size(self):
        return self.pointer_size

    def get_ranges_panel(self):
        return self.session_ui.ranges_panel

    def get_registers_panel(self):
        return self.session_ui.registers_panel

    def get_session_ui(self):
        return self.session_ui

    def on_script_destroyed(self):
        self.session_ui.hide()
        self.session_ui.on_script_destroyed()

        self.welcome_ui.show()
        self.welcome_ui.update_device_ui()

    def on_script_loaded(self):
        self.session_ui.on_script_loaded()

        self.welcome_ui.hide()
        self.session_ui.show()

        # trigger this to clear lists
        self.welcome_ui.on_device_changed()

    def set_arch(self, arch):
        self.arch = arch
        self.get_session_ui().asm_panel.on_arch_changed()
