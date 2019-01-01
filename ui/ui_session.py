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
from PyQt5.QtWidgets import QSplitter, QWidget, QVBoxLayout

from ui.panel_backtrace import BacktracePanel
from ui.panel_contexts import ContextsPanel
from ui.panel_hooks import HooksPanel
from ui.panel_log import LogPanel
from ui.panel_memory import MemoryPanel
from ui.panel_modules import ModulesPanel
from ui.panel_ranges import RangesPanel
from ui.panel_registers import RegistersPanel


class SessionUi(QSplitter):
    def __init__(self, app, *__args):
        super().__init__(*__args)

        self.app = app
        self.modules_panel = None
        self.ranges_panel = None
        self.registers_panel = None
        self.memory_panel = None
        self.log_panel = None
        self.backtrace_panel = None
        self.hooks_panel = None
        self.contexts_panel = None

        self.addWidget(self.build_left_column())
        self.addWidget(self.build_central_content())

        self.setHandleWidth(2)

        self.setStretchFactor(0, 3)
        self.setStretchFactor(1, 6)

    def build_left_column(self):
        splitter = QSplitter()
        splitter.setHandleWidth(2)
        splitter.setOrientation(Qt.Vertical)

        self.hooks_panel = HooksPanel(self.app)
        splitter.addWidget(self.hooks_panel)

        self.contexts_panel = ContextsPanel(self.app, 0, 3)
        splitter.addWidget(self.contexts_panel)

        self.backtrace_panel = BacktracePanel(self.app)
        splitter.addWidget(self.backtrace_panel)

        return splitter

    def build_central_content(self):
        q = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)

        splitter = QSplitter()
        splitter.setHandleWidth(2)

        main_panel = QSplitter(self)
        main_panel.setHandleWidth(2)
        main_panel.setOrientation(Qt.Vertical)

        self.registers_panel = RegistersPanel(self.app, 0, 4)
        main_panel.addWidget(self.registers_panel)

        self.memory_panel = MemoryPanel(self.app)
        main_panel.addWidget(self.memory_panel)

        self.log_panel = LogPanel(self.app)
        main_panel.addWidget(self.log_panel)

        main_panel.setStretchFactor(0, 1)
        main_panel.setStretchFactor(1, 3)
        main_panel.setStretchFactor(2, 1)
        splitter.addWidget(main_panel)

        right_splitter = QSplitter()
        right_splitter.setHandleWidth(2)
        right_splitter.setOrientation(Qt.Vertical)

        self.modules_panel = ModulesPanel(self.app, 0, 3)
        right_splitter.addWidget(self.modules_panel)

        self.ranges_panel = RangesPanel(self.app, 0, 4)
        right_splitter.addWidget(self.ranges_panel)

        splitter.addWidget(right_splitter)

        splitter.setStretchFactor(0, 5)
        splitter.setStretchFactor(1, 2)

        layout.addWidget(splitter)

        q.setLayout(layout)
        q.setContentsMargins(0, 0, 0, 0)

        return q
