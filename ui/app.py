import json
import threading

from PyQt5.QtGui import QIcon

from lib.dwarf import Dwarf
from ui.menu_bar import MenuBar
from ui.panel_backtrace import BacktracePanel
from ui.layout import Layout
from ui.panel_contexts import ContextsPanel
from ui.panel_hooks import HooksPanel

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import *

from ui.panel_log import LogPanel
from ui.panel_memory import MemoryPanel
from ui.panel_modules import ModulesPanel
from ui.panel_ranges import RangesPanel
from ui.panel_registers import RegistersPanel
from ui.panel_vars import VarsPanel


class AppWindow(QMainWindow):
    def __init__(self, script, flags=None, *args, **kwargs):
        super().__init__(flags, *args, **kwargs)

        self.app = App(self)
        self.dwarf = Dwarf(self, script)

        self.setWindowTitle("Dwarf")
        self.setWindowIcon(QIcon('ui/secret.png'))

        self.statusBar()

        self.menu = MenuBar(self)
        self.setCentralWidget(self.app)
        self.app.setup_ui()

    def get_app_instance(self):
        return self.app

    def get_dwarf(self):
        return self.dwarf


class App(QWidget):
    def __init__(self, app_window, flags=None, *args, **kwargs):
        super().__init__(flags, *args, **kwargs)

        self.app_window = app_window
        self.arch = ''
        self.pointer_size = 0

        self.modules_panel = None
        self.ranges_panel = None
        self.registers_panel = None
        self.memory_panel = None
        self.log_panel = None
        self.backtrace_panel = None
        self.hooks_panel = None
        self.contexts_panel = None
        self.vars_panel = None

        self.contexts = []

    def setup_ui(self):
        box = QVBoxLayout()

        main_splitter = Layout(self)
        main_splitter.addWidget(self.build_left_column())
        main_splitter.addWidget(self.build_central_content())
        main_splitter.setStretchFactor(0, 4)
        main_splitter.setStretchFactor(1, 5)

        box.addWidget(main_splitter)
        self.setLayout(box)

    def build_left_column(self):
        splitter = QSplitter()
        splitter.setOrientation(Qt.Vertical)

        self.hooks_panel = HooksPanel(self)
        splitter.addWidget(self.hooks_panel)

        self.contexts_panel = ContextsPanel(self, 0, 3)
        splitter.addWidget(self.contexts_panel)

        self.vars_panel = VarsPanel(self)
        splitter.addWidget(self.vars_panel)

        return splitter

    def build_central_content(self):
        q = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        splitter = QSplitter()

        main_panel = QSplitter(self)
        main_panel.setOrientation(Qt.Vertical)

        self.registers_panel = RegistersPanel(self, 0, 4)
        main_panel.addWidget(self.registers_panel)

        self.memory_panel = MemoryPanel(self)
        main_panel.addWidget(self.memory_panel)

        bottom_splitter = QSplitter()

        self.log_panel = LogPanel()
        bottom_splitter.addWidget(self.log_panel)

        self.backtrace_panel = BacktracePanel()
        bottom_splitter.addWidget(self.backtrace_panel)

        main_panel.addWidget(bottom_splitter)

        main_panel.setStretchFactor(0, 1)
        main_panel.setStretchFactor(1, 3)
        main_panel.setStretchFactor(2, 1)
        splitter.addWidget(main_panel)

        right_splitter = QSplitter()
        right_splitter.setOrientation(Qt.Vertical)

        self.modules_panel = ModulesPanel(self, 0, 3)
        right_splitter.addWidget(self.modules_panel)

        self.ranges_panel = RangesPanel(self, 0, 4)
        right_splitter.addWidget(self.ranges_panel)

        splitter.addWidget(right_splitter)

        splitter.setStretchFactor(0, 6)
        splitter.setStretchFactor(1, 4)

        layout.addWidget(splitter)

        q.setLayout(layout)
        q.setContentsMargins(0, 0, 0, 0)

        return q

    def restart(self):
        self.get_script().exports.restart()
        self.resume()
        self.get_hooks_panel().reset_hook_count()
        self.get_contexts_panel().setRowCount(0)

    def resume(self):
        self.contexts_panel.setRowCount(0)
        self.contexts.clear()
        self.registers_panel.setRowCount(0)
        self.backtrace_panel.setRowCount(0)
        self.get_script().exports.release()

    def set_modules(self, modules):
        self.modules_panel.set_modules(modules)

    def set_ranges(self, ranges):
        self.ranges_panel.set_ranges(ranges)

    def _apply_context(self, context):
        if 'modules' in context:
            self.set_modules(context['modules'])
        if 'ranges' in context:
            self.set_ranges(context['ranges'])
        if 'context' in context:
            self.registers_panel.set_context(context['context'])
        if 'backtrace' in context:
            self.backtrace_panel.set_backtrace(context['backtrace'])

    def apply_context(self, context):
        threading.Thread(target=self._apply_context, args=(context,)).start()

    def get_arch(self):
        return self.arch

    def get_contexts(self):
        return self.contexts

    def get_contexts_panel(self):
        return self.contexts_panel

    def get_hooks_panel(self):
        return self.hooks_panel

    def get_log_panel(self):
        return self.log_panel

    def get_memory_panel(self):
        return self.memory_panel

    def get_pointer_size(self):
        return self.pointer_size

    def get_registers_panel(self):
        return self.registers_panel

    def get_script(self):
        return self.app_window.get_dwarf().get_script()
