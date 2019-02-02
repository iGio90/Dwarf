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
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QSplitter, QTabWidget, QTabBar, QVBoxLayout, QWidget

from ui.panel_data import DataPanel


class SessionUi(QTabWidget):
    TAB_ASM = 'asm'
    TAB_DATA = 'data'
    TAB_EMULATOR = 'emulator'
    TAB_FTRACE = 'ftrace'
    TAB_JAVA_CLASSES = 'java'
    TAB_JAVA_TRACE = 'java_trace'
    TAB_MODULES = 'modules'
    TAB_RANGES = 'ranges'
    TAB_TRACE = 'trace'

    def __init__(self, app, *__args):
        super().__init__(*__args)

        self.app = app

        self.setTabsClosable(True)
        self.setMovable(True)
        self.tabCloseRequested.connect(self.close_tab)
        self.setContentsMargins(2, 2, 2, 2)
        self.setStyleSheet("""
            QListWidget:hover,
            QTableWidget:hover {
                border: 1px solid transparent;
            }
            QTabWidget QFrame{
                border: 0;
            }
            
            QTabWidget::pane {
                border: 0px solid transparent;
                border-radius: 0px;
                padding: 0px;
                margin: 0px;
            }
            
            QTabWidget::pane:selected {
                background-color: transparent;
                border: 0px solid transparent;
            }
            
            QWidget {
                padding: 0;
                margin-top: 2px;
                margin-right: 2px;
                margin-left: 1px;
            }
        """)

        self.session_panel = QSplitter()

        self.asm_panel = None
        self.backtrace_panel = None
        self.console_panel = None
        self.contexts_panel = None
        self.emulator_panel = None
        self.ftrace_panel = None
        self.hooks_panel = None
        self.java_class_panel = None
        self.java_explorer_panel = None
        self.java_trace_panel = None
        self.memory_panel = None
        self.modules_panel = None
        self.ranges_panel = None
        self.registers_panel = None
        self.trace_panel = None
        self.watchers_panel = None

        self.session_panel.addWidget(self.build_left_column())
        self.session_panel.addWidget(self.build_central_content())
        self.session_panel.addWidget(self.build_right_column())

        self.session_panel.setHandleWidth(1)
        self.session_panel.setStretchFactor(0, 2)
        self.session_panel.setStretchFactor(1, 6)
        self.session_panel.setStretchFactor(2, 2)
        self.session_panel.setContentsMargins(0, 0, 0, 0)

        self.addTab(self.session_panel, 'session')
        bt = self.tabBar().tabButton(0, QTabBar.LeftSide)
        if not bt:
            bt = self.tabBar().tabButton(0, QTabBar.RightSide)
        if bt:
            bt.resize(0, 0)
        self.add_main_tabs()

        self.data_panel = DataPanel(self.app)

    def add_main_tabs(self):
        self.add_dwarf_tab(SessionUi.TAB_MODULES)
        self.add_dwarf_tab(SessionUi.TAB_RANGES)

    def build_left_column(self):
        splitter = QSplitter()
        splitter.setHandleWidth(1)
        splitter.setOrientation(Qt.Vertical)
        splitter.setContentsMargins(0, 0, 0, 0)

        from ui.panel_hooks import HooksPanel
        self.hooks_panel = HooksPanel(self.app)
        splitter.addWidget(self.hooks_panel)

        from ui.panel_watchers import WatchersPanel
        self.watchers_panel = WatchersPanel(self.app)
        splitter.addWidget(self.watchers_panel)

        return splitter

    def build_central_content(self):
        main_panel = QSplitter(self)
        main_panel.setHandleWidth(1)
        main_panel.setOrientation(Qt.Vertical)
        main_panel.setContentsMargins(0, 0, 0, 0)

        from ui.panel_registers import RegistersPanel
        self.registers_panel = RegistersPanel(self.app, 0, 0)
        main_panel.addWidget(self.registers_panel)

        box = QVBoxLayout()
        box.setContentsMargins(0, 0, 0, 0)
        from ui.panel_memory import MemoryPanel
        self.memory_panel = MemoryPanel(self.app)
        box.addWidget(self.memory_panel)

        from ui.panel_java_explorer import JavaExplorerPanel
        self.java_explorer_panel = JavaExplorerPanel(self.app)
        self.java_explorer_panel.hide()
        box.addWidget(self.java_explorer_panel)

        q = QWidget()
        q.setLayout(box)
        main_panel.addWidget(q)

        from ui.panel_console import ConsolePanel
        self.console_panel = ConsolePanel(self.app)
        main_panel.addWidget(self.console_panel)

        main_panel.setStretchFactor(0, 1)
        main_panel.setStretchFactor(1, 3)
        main_panel.setStretchFactor(2, 1)
        return main_panel

    def build_right_column(self):
        splitter = QSplitter()
        splitter.setHandleWidth(1)
        splitter.setOrientation(Qt.Vertical)
        splitter.setContentsMargins(0, 0, 0, 0)

        from ui.panel_contexts import ContextsPanel
        self.contexts_panel = ContextsPanel(self.app)
        splitter.addWidget(self.contexts_panel)

        from ui.panel_backtrace import BacktracePanel
        self.backtrace_panel = BacktracePanel(self.app)
        splitter.addWidget(self.backtrace_panel)

        return splitter

    def on_script_loaded(self):
        pass

    def on_script_destroyed(self):
        for i in range(0, self.count()):
            if i > 0:
                self.removeTab(i)

        self.contexts_panel.clear()
        self.console_panel.clear()
        if self.data_panel is not None:
            self.data_panel.clear()
        if self.watchers_panel is not None:
            self.watchers_panel.clear()

        if self.asm_panel is not None:
            self.asm_panel.clear()

        self.hooks_panel.setRowCount(0)
        self.hooks_panel.setColumnCount(0)

        if self.ranges_panel is not None:
            self.ranges_panel.setRowCount(0)

        if self.modules_panel is not None:
            self.modules_panel.setRowCount(0)

        self.backtrace_panel.setRowCount(0)
        self.backtrace_panel.setColumnCount(0)

        self.registers_panel.setRowCount(0)
        self.registers_panel.setColumnCount(0)

        self.memory_panel.on_script_destroyed()

        self.ftrace_panel = None
        self.java_class_panel = None
        self.java_explorer_panel = None
        self.java_trace_panel = None
        self.trace_panel = None

    def close_tab(self, index):
        w = self.widget(index)

        try:
            w.on_tab_closed()
        except:
            pass

        # invalidate the object in the current session
        # this is the fastest way i can think to achieve this
        v = vars(self)
        for obj in v:
            if v[obj] is not None and v[obj] == w:
                try:
                    v[obj].clear()
                except:
                    pass
                # prevent data panel to be nullified
                if not isinstance(v[obj], DataPanel):
                    v[obj] = None
        self.removeTab(index)

    def add_dwarf_tab(self, tab_id, request_focus=False):
        if tab_id == SessionUi.TAB_ASM:
            if self.asm_panel is None:
                from ui.panel_asm import AsmPanel
                self.asm_panel = AsmPanel(self.app)
            self.addTab(self.asm_panel, 'asm')
            if request_focus:
                self.setCurrentWidget(self.asm_panel)
            return self.asm_panel
        elif tab_id == SessionUi.TAB_DATA:
            if self.data_panel is None:
                from ui.panel_data import DataPanel
                self.data_panel = DataPanel(self.app)
            self.addTab(self.data_panel, 'data')
            if request_focus:
                self.setCurrentWidget(self.data_panel)
            return self.hooks_panel
        elif tab_id == SessionUi.TAB_EMULATOR:
            if self.emulator_panel is None:
                from ui.panel_emulator import EmulatorPanel
                self.emulator_panel= EmulatorPanel(self.app)
            self.addTab(self.emulator_panel, 'emulator')
            if request_focus:
                self.setCurrentWidget(self.emulator_panel)
            return self.trace_panel
        elif tab_id == SessionUi.TAB_FTRACE:
            if self.ftrace_panel is None:
                from ui.panel_ftrace import FTracePanel
                self.ftrace_panel = FTracePanel(self.app)
            self.addTab(self.ftrace_panel, 'ftrace')
            if request_focus:
                self.setCurrentWidget(self.ftrace_panel)
            return self.trace_panel
        elif tab_id == SessionUi.TAB_JAVA_CLASSES:
            if self.java_class_panel is None:
                from ui.panel_java_classes import JavaClassesPanel
                self.java_class_panel = JavaClassesPanel(self.app)
            self.addTab(self.java_class_panel, 'java classes')
            if request_focus:
                self.setCurrentWidget(self.java_class_panel)
            return self.java_class_panel
        elif tab_id == SessionUi.TAB_JAVA_TRACE:
            if self.java_trace_panel is None:
                from ui.panel_java_trace import JavaTracePanel
                self.java_trace_panel = JavaTracePanel(self.app)
            self.addTab(self.java_trace_panel, 'java trace')
            if request_focus:
                self.setCurrentWidget(self.java_trace_panel)
            return self.java_trace_panel
        elif tab_id == SessionUi.TAB_MODULES:
            if self.modules_panel is None:
                from ui.panel_modules import ModulesPanel
                self.modules_panel = ModulesPanel(self.app)
            self.addTab(self.modules_panel, 'modules')
            if request_focus:
                self.setCurrentWidget(self.modules_panel)
            return self.modules_panel
        elif tab_id == SessionUi.TAB_RANGES:
            if self.ranges_panel is None:
                from ui.panel_ranges import RangesPanel
                self.ranges_panel = RangesPanel(self.app)
            self.addTab(self.ranges_panel, 'ranges')
            if request_focus:
                self.setCurrentWidget(self.ranges_panel)
            return self.ranges_panel
        elif tab_id == SessionUi.TAB_TRACE:
            if self.trace_panel is None:
                from ui.panel_trace import TracePanel
                self.trace_panel = TracePanel(self.app)
            self.addTab(self.trace_panel, 'trace')
            if request_focus:
                self.setCurrentWidget(self.trace_panel)
            return self.trace_panel

    def add_tab(self, tab_widget, tab_label):
        self.addTab(tab_widget, tab_label)
        self.setCurrentWidget(tab_widget)

    def disasm(self, ptr=0, _range=None):
        self.add_dwarf_tab(SessionUi.TAB_ASM, True)
        if _range:
            self.asm_panel.disasm(_range=_range)
        else:
            self.asm_panel.read_memory(ptr)

    def request_session_ui_focus(self):
        self.setCurrentWidget(self.session_panel)

    def show_java_panel(self):
        self.memory_panel.hide()
        self.java_explorer_panel.show()

    def show_memory_panel(self):
        self.java_explorer_panel.hide()
        self.memory_panel.show()
