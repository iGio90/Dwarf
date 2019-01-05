"""
Dwarf - Copyright (C) 2018 iGio90

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
from PyQt5.QtWidgets import QSplitter, QTabWidget, QTabBar

from ui.panel_asm import AsmPanel
from ui.panel_data import DataPanel
from ui.panel_backtrace import BacktracePanel
from ui.panel_contexts import ContextsPanel
from ui.panel_hooks import HooksPanel
from ui.panel_log import LogPanel
from ui.panel_memory import MemoryPanel
from ui.panel_modules import ModulesPanel
from ui.panel_ranges import RangesPanel
from ui.panel_registers import RegistersPanel


class SessionUi(QTabWidget):
    TAB_MODULES = 0
    TAB_RANGES = 1
    TAB_DATA = 2
    TAB_ASM = 3

    def __init__(self, app, *__args):
        super().__init__(*__args)

        self.app = app

        self.setTabsClosable(True)
        self.setMovable(True)
        self.tabCloseRequested.connect(self.removeTab)
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

        self.modules_panel = None
        self.ranges_panel = None
        self.registers_panel = None
        self.memory_panel = None
        self.log_panel = None
        self.backtrace_panel = None
        self.hooks_panel = None
        self.contexts_panel = None

        self.data_panel = DataPanel(self.app)
        self.asm_panel = AsmPanel(self.app)

        self.session_panel.addWidget(self.build_left_column())
        self.session_panel.addWidget(self.build_central_content())

        self.session_panel.setHandleWidth(1)
        self.session_panel.setStretchFactor(0, 2)
        self.session_panel.setStretchFactor(1, 6)
        self.session_panel.setContentsMargins(0, 0, 0, 0)

        self.addTab(self.session_panel, 'session')
        bt = self.tabBar().tabButton(0, QTabBar.LeftSide)
        if not bt:
            bt = self.tabBar().tabButton(0, QTabBar.RightSide)
        if bt:
            bt.resize(0, 0)

        self.modules_panel = ModulesPanel(self.app)
        self.ranges_panel = RangesPanel(self.app)

        self.add_dwarf_tab(SessionUi.TAB_MODULES)
        self.add_dwarf_tab(SessionUi.TAB_RANGES)

    def build_left_column(self):
        splitter = QSplitter()
        splitter.setHandleWidth(1)
        splitter.setOrientation(Qt.Vertical)
        splitter.setContentsMargins(0, 0, 0, 0)

        self.hooks_panel = HooksPanel(self.app)
        splitter.addWidget(self.hooks_panel)

        self.contexts_panel = ContextsPanel(self.app)
        splitter.addWidget(self.contexts_panel)

        self.backtrace_panel = BacktracePanel(self.app)
        splitter.addWidget(self.backtrace_panel)

        return splitter

    def build_central_content(self):
        main_panel = QSplitter(self)
        main_panel.setHandleWidth(1)
        main_panel.setOrientation(Qt.Vertical)
        main_panel.setContentsMargins(0, 0, 0, 0)

        self.registers_panel = RegistersPanel(self.app, 0, 4)
        main_panel.addWidget(self.registers_panel)

        self.memory_panel = MemoryPanel(self.app)
        main_panel.addWidget(self.memory_panel)

        self.log_panel = LogPanel(self.app)
        main_panel.addWidget(self.log_panel)

        main_panel.setStretchFactor(0, 1)
        main_panel.setStretchFactor(1, 3)
        main_panel.setStretchFactor(2, 1)
        return main_panel

    def on_script_destroyed(self):
        self.log_panel.clear()
        self.data_panel.clear()

        self.hooks_panel.setRowCount(0)
        self.hooks_panel.resizeColumnsToContents()
        self.hooks_panel.horizontalHeader().setStretchLastSection(True)

        self.ranges_panel.setRowCount(0)
        self.ranges_panel.resizeColumnsToContents()
        self.ranges_panel.horizontalHeader().setStretchLastSection(True)

        self.modules_panel.setRowCount(0)
        self.modules_panel.resizeColumnsToContents()
        self.modules_panel.horizontalHeader().setStretchLastSection(True)

        self.contexts_panel.setRowCount(0)
        self.contexts_panel.resizeColumnsToContents()
        self.contexts_panel.horizontalHeader().setStretchLastSection(True)

        self.backtrace_panel.setRowCount(0)
        self.backtrace_panel.resizeColumnsToContents()
        self.backtrace_panel.horizontalHeader().setStretchLastSection(True)

        self.registers_panel.setRowCount(0)
        self.registers_panel.resizeColumnsToContents()
        self.registers_panel.horizontalHeader().setStretchLastSection(True)

        self.memory_panel.on_script_destroyed()

    def close_tab(self, index):
        self.removeTab(index)

    def add_dwarf_tab(self, tab_id, request_focus=False):
        if tab_id == SessionUi.TAB_DATA:
            self.addTab(self.data_panel, 'data')
            if request_focus:
                self.setCurrentWidget(self.hooks_panel)
        elif tab_id == SessionUi.TAB_MODULES:
            self.addTab(self.modules_panel, 'modules')
            if request_focus:
                self.setCurrentWidget(self.modules_panel)
        elif tab_id == SessionUi.TAB_RANGES:
            self.addTab(self.ranges_panel, 'ranges')
            if request_focus:
                self.setCurrentWidget(self.ranges_panel)
        elif tab_id == SessionUi.TAB_ASM:
            self.addTab(self.asm_panel, 'asm')
            if request_focus:
                self.setCurrentWidget(self.asm_panel)

    def add_search_tab(self, search_panel_widget, search_label):
        if len(search_label) > 5:
            search_label = search_label[:4] + '...'
        self.addTab(search_panel_widget, 'search - %s' % search_label)
        self.setCurrentWidget(search_panel_widget)

    def disasm(self, ptr=0, _range=None):
        self.add_dwarf_tab(SessionUi.TAB_ASM, True)
        if _range:
            self.asm_panel.disasm(_range=_range)
        else:
            self.asm_panel.read_memory(ptr)

    def request_session_ui_focus(self):
        self.setCurrentWidget(self.session_panel)
