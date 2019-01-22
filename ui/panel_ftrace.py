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
from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QSplitter, QLabel, QTextEdit, QScrollBar, \
    QListWidget, QDialog

from lib.kernel import FTrace
from ui.widget_item_not_editable import NotEditableListWidgetItem


class FTraceReadDialog(QDialog):
    def __init__(self, flags=None, *args, **kwargs):
        super().__init__(flags, *args, **kwargs)

        layout = QVBoxLayout()
        self.list = QListWidget()
        layout.addWidget(self.list)
        self.setLayout(layout)

    def show(self):
        self.showMaximized()
        self.exec_()

    def append(self, data):
        data = data.replace('\n', '')
        self.list.addItem(NotEditableListWidgetItem(data))


class FTracePanel(QWidget):
    def __init__(self, app, flags=None, *args, **kwargs):
        super().__init__(flags, *args, **kwargs)
        self.app = app

        self.kernel = app.get_dwarf().get_kernel()
        self.ftrace = self.kernel.get_ftrace()
        self.trace_read_dialog = None

        layout = QVBoxLayout()

        central_layout = QVBoxLayout()

        self.options = QSplitter()
        self.filter_functions = QTextEdit()
        self.filter_events = QTextEdit()
        self.options_list = QListWidget()

        self.setup_options_view()

        central_layout.addWidget(self.options)

        self.buttons = QHBoxLayout()
        self.btn_pause = QPushButton('pause')
        self.btn_trace = QPushButton('start')
        self.btn_read = QPushButton('read')

        self.btn_pause.setEnabled(False)

        self.btn_pause.clicked.connect(self.pause_clicked)
        self.btn_trace.clicked.connect(self.trace_clicked)
        self.btn_read.clicked.connect(self.read_clicked)

        self.buttons.addWidget(self.btn_pause)
        self.buttons.addWidget(self.btn_trace)
        self.buttons.addWidget(self.btn_read)

        layout.addLayout(self.buttons)
        layout.addLayout(central_layout)

        self.setLayout(layout)

    def append_data(self, data):
        if self.trace_read_dialog is not None:
            self.trace_read_dialog.append(data)

    def disable_options_view(self):
        self.btn_pause.setEnabled(True)
        self.btn_trace.setText('stop')
        self.btn_read.setEnabled(False)
        self.options_list.setEnabled(False)
        self.filter_events.setEnabled(False)
        self.filter_functions.setEnabled(False)

    def enable_options_view(self):
        self.btn_pause.setEnabled(False)
        self.btn_trace.setText('start')
        self.btn_read.setEnabled(True)
        self.options_list.setEnabled(True)
        self.filter_events.setEnabled(True)
        self.filter_functions.setEnabled(True)

    def setup_options_view(self):
        self.options.setOrientation(Qt.Horizontal)
        self.options.setHandleWidth(1)

        filter_functions_layout = QVBoxLayout()
        filter_functions_layout.addWidget(QLabel("Filter functions"))

        bar = QScrollBar()
        bar.setFixedHeight(0)
        bar.setFixedWidth(0)

        self.filter_functions.setHorizontalScrollBar(bar)
        self.filter_functions.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.filter_functions.setPlainText(self.ftrace.get_current_filters())
        self.filter_functions.setPlaceholderText("*SyS_open*")
        filter_functions_layout.addWidget(self.filter_functions)

        filter_events_layout = QVBoxLayout()
        filter_events_layout.addWidget(QLabel("Filter events"))

        bar = QScrollBar()
        bar.setFixedHeight(0)
        bar.setFixedWidth(0)

        self.filter_events.setHorizontalScrollBar(bar)
        self.filter_events.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.filter_events.setPlainText(self.ftrace.get_current_events())
        self.filter_events.setPlaceholderText('raw_syscalls:sys_exit\nraw_syscalls:sys_enter')
        filter_events_layout.addWidget(self.filter_events)

        filter_functions_widget = QWidget()
        filter_functions_widget.setLayout(filter_functions_layout)
        filter_events_widget = QWidget()
        filter_events_widget.setLayout(filter_events_layout)

        options_list_layout = QVBoxLayout()
        options_list_layout.addWidget(QLabel("Options"))

        for option in self.ftrace.get_options():
            if len(option) < 1:
                continue

            q = NotEditableListWidgetItem()
            q.setFlags(Qt.ItemIsUserCheckable | Qt.ItemIsEnabled)

            if not option.startswith('no'):
                q.setCheckState(Qt.Checked)
                q.setText(option)
            else:
                q.setCheckState(Qt.Unchecked)
                q.setText(option[2:])
            self.options_list.addItem(q)

        options_list_layout.addWidget(self.options_list)

        options_list_widget = QWidget()
        options_list_widget.setLayout(options_list_layout)

        self.options.addWidget(filter_functions_widget)
        self.options.addWidget(filter_events_widget)
        self.options.addWidget(options_list_widget)

    def pause_clicked(self):
        if self.ftrace.state == FTrace.STATE_TRACING:
            self.ftrace.pause()
            self.btn_read.setEnabled(True)
            self.btn_trace.setText("resume")

    def read_clicked(self):
        self.trace_read_dialog = FTraceReadDialog()

        self.ftrace.read_trace_async()

        self.trace_read_dialog.show()

    def trace_clicked(self):
        if self.ftrace.state == FTrace.STATE_TRACING:
            self.ftrace.stop()
            self.enable_options_view()
        elif self.ftrace.state == FTrace.STATE_NOT_TRACING:
            self.ftrace.set_current_events(self.filter_events.toPlainText())
            self.ftrace.set_current_filters(self.filter_functions.toPlainText())

            for i in range(0, self.options_list.count()):
                item = self.options_list.item(i)
                option = item.text()
                enabled = True
                if item.checkState() == Qt.Unchecked:
                    enabled = False
                self.ftrace.set_option(option, enabled)

            self.ftrace.start()
            self.disable_options_view()
        else:
            self.ftrace.start()
            self.disable_options_view()
