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
from PyQt5.QtWidgets import QSplitter, QListWidget, QScrollBar, QMenu, QWidget, QVBoxLayout, QPushButton

from ui.dialog_input import InputDialog, QHBoxLayout
from ui.widget_item_not_editable import NotEditableListWidgetItem


# a list of classes you generally want to trace
PREFIXED_CLASS = [
    'android.util.Base64',
    'java.security.MessageDigest',
    'java.util.zip.GZIPOutputStream'
]


class JavaTracePanel(QWidget):
    def __init__(self, app, *__args):
        super().__init__(app)
        self.app = app

        self.tracing = False
        self.trace_classes = []
        self.trace_depth = 0

        layout = QVBoxLayout()
        buttons = QHBoxLayout()

        self.btn_start = QPushButton('start')
        self.btn_start.clicked.connect(self.start_trace)
        self.btn_pause = QPushButton('pause')
        self.btn_pause.setEnabled(False)
        self.btn_pause.clicked.connect(self.pause_trace)
        self.btn_stop = QPushButton('stop')
        self.btn_stop.setEnabled(False)
        self.btn_stop.clicked.connect(self.stop_trace)

        buttons.addWidget(self.btn_start)
        buttons.addWidget(self.btn_pause)
        buttons.addWidget(self.btn_stop)
        layout.addLayout(buttons)

        self.setup_splitter = QSplitter()
        self.events_list = QListWidget()
        self.events_list.setVisible(False)

        self.trace_list = QListWidget()
        self.class_list = QListWidget()

        self.trace_list.itemDoubleClicked.connect(self.trace_list_double_click)

        self.class_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.class_list.customContextMenuRequested.connect(self.show_class_list_menu)
        self.class_list.itemDoubleClicked.connect(self.class_list_double_click)

        self.current_class_search = ''

        bar = QScrollBar()
        bar.setFixedWidth(0)
        bar.setFixedHeight(0)
        self.trace_list.setHorizontalScrollBar(bar)
        bar = QScrollBar()
        bar.setFixedWidth(0)
        bar.setFixedHeight(0)
        self.class_list.setHorizontalScrollBar(bar)

        self.setup_splitter.addWidget(self.trace_list)
        self.setup_splitter.addWidget(self.class_list)
        self.setup_splitter.setHandleWidth(1)

        layout.addWidget(self.setup_splitter)
        layout.addWidget(self.events_list)

        self.setLayout(layout)

    def class_list_double_click(self, item):
        try:
            if self.trace_classes.index(item.text()) >= 0:
                return
        except:
            pass
        self.trace_classes.append(item.text())
        q = NotEditableListWidgetItem(item.text())
        self.trace_list.addItem(q)
        self.trace_list.sortItems()

    def on_enumeration_start(self):
        self.class_list.clear()

    def on_enumeration_match(self, java_class):
        try:
            if PREFIXED_CLASS.index(java_class) >= 0:
                try:
                    if self.trace_classes.index(java_class) >= 0:
                        return
                except:
                    pass
                q = NotEditableListWidgetItem(java_class)
                self.trace_list.addItem(q)
                self.trace_classes.append(java_class)
        except:
            pass

        q = NotEditableListWidgetItem(java_class)
        self.class_list.addItem(q)

    def on_enumeration_complete(self):
        self.class_list.sortItems()
        self.trace_list.sortItems()

    def on_event(self, event, clazz, data):
        if event == 'leave':
            indicator = '<------'
            if self.trace_depth > 0:
                self.trace_depth -= 1
        else:
            indicator = '------>'

        if self.trace_depth == 0 and self.events_list.count() > 0 and event == 'enter':
            q = NotEditableListWidgetItem('')
            q.setFlags(Qt.NoItemFlags)
            self.events_list.addItem(q)

        q = NotEditableListWidgetItem('%s%s\t%s\t\t%s' % (
            ' ' * (4 * self.trace_depth), indicator, clazz, data
        ))
        self.events_list.addItem(q)

        if event == 'enter':
            self.trace_depth += 1

    def pause_trace(self):
        self.app.dwarf_api('stopJavaTracer')
        self.tracing = False
        self.btn_stop.setEnabled(True)
        self.btn_pause.setEnabled(False)
        self.btn_start.setEnabled(True)

    def search(self):
        accept, input = InputDialog.input(self.app, hint='Search',
                                          input_content=self.current_class_search,
                                          placeholder='Search something...')
        if accept:
            self.current_class_search = input.lower()
            for i in range(0, self.class_list.count()):
                try:
                    if self.class_list.item(i).text().lower().index(self.current_class_search.lower()) >= 0:
                        self.class_list.setRowHidden(i, False)
                except:
                    self.class_list.setRowHidden(i, True)

    def show_class_list_menu(self, pos):
        menu = QMenu()
        search = menu.addAction('Search')
        action = menu.exec_(self.class_list.mapToGlobal(pos))
        if action:
            if action == search:
                self.search()

    def start_trace(self):
        self.app.dwarf_api('startJavaTracer', [self.trace_classes])
        self.trace_depth = 0
        self.tracing = True
        self.setup_splitter.setVisible(False)
        self.events_list.setVisible(True)
        self.btn_stop.setEnabled(True)
        self.btn_pause.setEnabled(True)
        self.btn_start.setEnabled(False)

    def stop_trace(self):
        self.app.dwarf_api('stopJavaTracer')
        self.tracing = False
        self.setup_splitter.setVisible(True)
        self.events_list.setVisible(False)
        self.events_list.clear()
        self.btn_stop.setEnabled(False)
        self.btn_pause.setEnabled(False)
        self.btn_start.setEnabled(True)

    def trace_list_double_click(self, item):
        try:
            index = self.trace_classes.index(item.text())
        except:
            return
        if index < 0:
            return
        self.trace_classes.pop(index)
        self.trace_list.takeItem(self.trace_list.row(item))

    def keyPressEvent(self, event):
        if event.modifiers() & Qt.ControlModifier:
            if event.key() == Qt.Key_F:
                self.search()
        super(JavaTracePanel, self).keyPressEvent(event)
