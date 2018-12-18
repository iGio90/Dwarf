from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QListWidget, QListWidgetItem, QSplitter, QTableWidget, QTableWidgetItem, QTabWidget

from ui.panel_memory import MemoryPanel
from ui.panel_registers import RegistersPanel
from ui.widget_context import ContextItem
from ui.widget_item_not_editable import NotEditableListWidgetItem, NotEditableTableWidgetItem


class MainPanel(QSplitter):
    def __init__(self, app):
        super().__init__()
        self.app = app

        self.setOrientation(Qt.Vertical)

        top_splitter = QSplitter()

        self.registers_panel = RegistersPanel(self.app, 0, 4)
        top_splitter.addWidget(self.registers_panel)

        top_splitter.setStretchFactor(0, 1)
        top_splitter.setStretchFactor(1, 3)
        self.addWidget(top_splitter)

        self.memory_panel = MemoryPanel(self.app, 0, 18)
        self.addWidget(self.memory_panel)

        bottom_splitter = QSplitter()

        self.log_panel = QListWidget()
        bottom_splitter.addWidget(self.log_panel)

        bottom_splitter.setStretchFactor(0, 1)
        bottom_splitter.setStretchFactor(1, 3)
        self.addWidget(bottom_splitter)

        self.setStretchFactor(0, 1)
        self.setStretchFactor(1, 3)
        self.setStretchFactor(2, 1)

    def add_to_main_content_content(self, what, clear=False, scroll=False):
        if clear:
            self.log_panel.clear()

        if isinstance(what, QListWidgetItem):
            self.log_panel.addItem(what)
        else:
            item = NotEditableListWidgetItem(what)
            self.log_panel.addItem(item)

        if scroll:
            self.log_panel.scrollToBottom()

    def release_target(self, tid=0):
        self.registers_panel.setRowCount(0)

    def set_context(self, context):
        self.registers_panel.set_context(context)

    def get_memory_panel(self):
        return self.memory_panel
