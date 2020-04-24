"""
    Dwarf - Copyright (C) 2018-2020 Giovanni Rocca (iGio90)

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
import json
from math import ceil, floor

from PyQt5 import QtCore, QtGui, QtWidgets

from dwarf_debugger.ui.widgets.list_view import DwarfListView

from dwarf_debugger.lib import utils


class JavaTraceView(QtWidgets.QAbstractScrollArea):

    def __init__(self, parent=None):
        super().__init__(parent=parent)

        self.data = []
        self.search_result = []

        # setting font
        self.font = utils.get_os_monospace_font()
        self.font.setFixedPitch(True)
        self.setFont(self.font)

        self._char_width = self.fontMetrics().width("2")
        self._char_height = self.fontMetrics().height()
        self._base_line = self.fontMetrics().ascent()
        self._has_scrolled = False

        self._data_height = 0

        self.verticalScrollBar().rangeChanged.connect(self._scroll_bottom)
        self.verticalScrollBar().valueChanged.connect(self._check_scroll)

    def add_event(self, data):
        self.data.append(data)
        maximum = len(self.data) - self.visible_lines() + 1
        if self._data_height > maximum:
            maximum = int(ceil(self._data_height / self._char_height))
        self.verticalScrollBar().setRange(0, maximum)
        self.verticalScrollBar().setPageStep(self.visible_lines())

    def _scroll_bottom(self, scroll_min, scroll_max):
        if not self._has_scrolled:
            self.verticalScrollBar().setValue(scroll_max)

    def _check_scroll(self, value):
        if value < self.verticalScrollBar().maximum():
            # user scrolled so stop autoscroll
            self._has_scrolled = True
        elif value == self.verticalScrollBar().maximum():
            # scrolled back to bottom so do autoscroll again
            self._has_scrolled = False

    def visible_lines(self):
        """ returns number of lines that fits viewport
        """
        height = self.viewport().height()
        num_lines = int(ceil(height / self._char_height))
        return num_lines + 1

    # def adjust(self):
    #    for x in self.data:

    def paintEvent(self, event):
        painter = QtGui.QPainter(self.viewport())
        painter.fillRect(0, 0, self.viewport().width(),
                         self.viewport().height(), QtGui.QColor('#181818'))

        self.pos = self.verticalScrollBar().value()
        data_start = 0
        data_end = 0

        if len(self.data) > self.visible_lines():
            data_start = self.pos
            data_end = self.pos + self.visible_lines()
        else:
            data_end = len(self.data)

        drawing_pos_y = 10
        trace_depth = 0

        fontMetrics = QtGui.QFontMetrics(QtGui.QFont(self.font))
        text_options = QtGui.QTextOption()
        text_options.setAlignment(QtCore.Qt.AlignLeft)
        text_options.setWrapMode(
            QtGui.QTextOption.WrapAtWordBoundaryOrAnywhere)

        for i, line in enumerate(self.data):
            if i == self.pos:
                break
            """if line['event'] == 'leave':
                trace_depth -= 1
            elif line['event'] == 'enter':
                trace_depth += 1"""

        for i, line in enumerate(self.data[data_start:data_end]):
            if i > self.visible_lines():
                break

            is_obj = False
            if isinstance(line['data'], str) and line['data'].startswith('{'):
                is_obj = True
                line['data'] = json.loads(line['data'])

            drawing_pos_x = 10
            painter.setPen(QtGui.QColor('#fff'))

            if line['event'] == 'leave':
                """if trace_depth:
                    trace_depth -= 1"""
                drawing_pos_x += (1 * 20)
                painter.setPen(QtGui.QColor('crimson'))
                painter.setBrush(QtGui.QColor('#222'))
                polygon = QtGui.QPolygon()
                polygon.append(
                    QtCore.QPoint(drawing_pos_x - 6, drawing_pos_y + (self._char_height * 0.5)))
                polygon.append(QtCore.QPoint(drawing_pos_x + 10,
                                             drawing_pos_y - (self._char_height * 0.5)))
                polygon.append(QtCore.QPoint(self.viewport().width() -
                                             21, drawing_pos_y - (self._char_height * 0.5)))
                polygon.append(QtCore.QPoint(self.viewport().width(
                ) - 21, drawing_pos_y + self._char_height + (self._char_height * 0.5)))
                polygon.append(QtCore.QPoint(drawing_pos_x + 10, drawing_pos_y +
                                             self._char_height + (self._char_height * 0.5)))
                polygon.append(
                    QtCore.QPoint(drawing_pos_x - 6, drawing_pos_y + (self._char_height * 0.5)))
                painter.drawPolygon(polygon)
            elif line['event'] == 'enter':
                #trace_depth += 1
                drawing_pos_x += (1 * 20)
                painter.setPen(QtGui.QColor('yellowgreen'))
                painter.setBrush(QtGui.QColor('#222'))
                polygon = QtGui.QPolygon()
                polygon.append(
                    QtCore.QPoint(drawing_pos_x + 6, drawing_pos_y - (self._char_height * 0.5)))
                polygon.append(QtCore.QPoint(int(floor(self.viewport().width())) -
                                             21, drawing_pos_y - (self._char_height * 0.5)))
                polygon.append(QtCore.QPoint(int(floor(self.viewport().width())) -
                                             5, drawing_pos_y + (self._char_height * 0.5)))
                polygon.append(QtCore.QPoint(int(floor(self.viewport().width())) - 21,
                                             drawing_pos_y + self._char_height + (self._char_height * 0.5)))
                polygon.append(QtCore.QPoint(drawing_pos_x + 6, drawing_pos_y +
                                             self._char_height + (self._char_height * 0.5)))
                # polygon.append(QtCore.QPoint(drawing_pos_x + 21, drawing_pos_y + (self._char_height * 0.5)))
                polygon.append(
                    QtCore.QPoint(drawing_pos_x + 6, drawing_pos_y - (self._char_height * 0.5)))
                painter.drawPolygon(polygon)

            drawing_pos_x += 20
            rect = QtCore.QRectF(drawing_pos_x, drawing_pos_y, self.viewport(
            ).width() - 25 - drawing_pos_x, self._char_height + 10)

            if line['event'] == 'enter':
                arg_str = '('
                for a in range(len(line['data'])):
                    arg_str += 'arg_{0}, '.format(a)

                if line['data']:
                    arg_str = arg_str[:-2]
                arg_str += ')'
                painter.drawText(
                    rect, line['class'] + arg_str, option=text_options)
            else:
                painter.drawText(rect, line['class'], option=text_options)

            drawing_pos_y += self._char_height + 15

            if isinstance(line['data'], str):
                if line['data']:
                    rect = fontMetrics.boundingRect(drawing_pos_x, drawing_pos_y, self.viewport().width(
                    ) - drawing_pos_x - 25, 0, QtCore.Qt.AlignLeft | QtCore.Qt.TextWordWrap | QtCore.Qt.TextWrapAnywhere, line['data'])
                    rect = QtCore.QRectF(drawing_pos_x, drawing_pos_y,
                                         rect.width(), rect.height())
                    painter.setPen(QtGui.QColor('#888'))
                    painter.drawText(rect, line['data'], option=text_options)
                    drawing_pos_y += rect.height() + 5
            else:
                width = int(floor(self.viewport().width() -
                                  drawing_pos_x - (5 * self._char_width) - 35))
                max_chars = int(floor(width / self._char_width))
                hold_x = drawing_pos_x + 5
                width -= 20
                painter.setPen(QtGui.QColor('#888'))
                for data in line['data']:
                    drawing_pos_x = hold_x
                    if isinstance(line['data'][data], int):
                        text = '{0:d}'.format(line['data'][data])
                    elif isinstance(line['data'][data], str):
                        text = line['data'][data]
                    elif isinstance(line['data'][data], list):
                        text = str(line['data'][data])
                    else:
                        text = str(line['data'][data])

                    if line['event'] == 'enter':
                        arg = 'arg_{0}: '.format(data)
                        painter.drawText(
                            drawing_pos_x, drawing_pos_y + self._base_line, arg)
                        drawing_pos_x += len(arg) * self._char_width
                    elif line['event'] == 'leave':
                        retval = data + ': '
                        painter.drawText(
                            drawing_pos_x, drawing_pos_y + self._base_line, retval)
                        drawing_pos_x += len(retval) * self._char_width

                    if len(text) * self._char_width < width:
                        painter.drawText(
                            drawing_pos_x, drawing_pos_y + self._base_line, text)
                        drawing_pos_y += self._char_height + 5
                    else:
                        rect = fontMetrics.boundingRect(
                            drawing_pos_x, drawing_pos_y, width, 0, QtCore.Qt.AlignLeft | QtCore.Qt.TextWordWrap | QtCore.Qt.TextWrapAnywhere, text)
                        rect = QtCore.QRectF(rect)
                        painter.drawText(rect, text, option=text_options)
                        drawing_pos_y += rect.height() + 5

            drawing_pos_y += self._char_height + 5
            # self._data_height += drawing_pos_y

    def clear(self):
        self.data = []


class JavaTracePanel(QtWidgets.QWidget):
    def __init__(self, app, *__args):
        super().__init__(app)
        self.app = app

        self.app.dwarf.onJavaTraceEvent.connect(self.on_event)
        self.app.dwarf.onEnumerateJavaClassesStart.connect(
            self.on_enumeration_start)
        self.app.dwarf.onEnumerateJavaClassesMatch.connect(
            self.on_enumeration_match)
        self.app.dwarf.onEnumerateJavaClassesComplete.connect(
            self.on_enumeration_complete)

        self.tracing = False
        self.trace_depth = 0

        # a list of classes you generally want to trace
        self._prefixed_classes = [
            'android.util.Base64',
            'java.security.MessageDigest',
            'java.util.zip.GZIPOutputStream'
        ]

        layout = QtWidgets.QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self._record_icon = QtGui.QIcon(
            utils.resource_path('assets/icons/record.png'))
        self._pause_icon = QtGui.QIcon(
            utils.resource_path('assets/icons/pause.png'))
        self._stop_icon = QtGui.QIcon(
            utils.resource_path('assets/icons/stop.png'))

        self._tool_bar = QtWidgets.QToolBar()
        self._tool_bar.addAction('Start', self.start_trace)
        self._tool_bar.addAction('Pause', self.pause_trace)
        self._tool_bar.addAction('Stop', self.stop_trace)
        self._tool_bar.addSeparator()
        self._entries_lbl = QtWidgets.QLabel('Events: 0')
        self._entries_lbl.setStyleSheet('color: #ef5350;')
        self._entries_lbl.setContentsMargins(10, 0, 10, 2)
        self._entries_lbl.setAttribute(
            QtCore.Qt.WA_TranslucentBackground, True)  # keep this
        self._entries_lbl.setAlignment(
            QtCore.Qt.AlignRight | QtCore.Qt.AlignVCenter)
        self._entries_lbl.setSizePolicy(
            QtWidgets.QSizePolicy.Expanding, QtWidgets.QSizePolicy.Preferred)
        self._tool_bar.addWidget(self._entries_lbl)

        layout.addWidget(self._tool_bar)

        self.setup_splitter = QtWidgets.QSplitter()
        self.events_list = JavaTraceView(self)
        self.events_list.setVisible(False)

        self.trace_list = DwarfListView()
        self.trace_list_model = QtGui.QStandardItemModel(0, 1)
        self.trace_list_model.setHeaderData(0, QtCore.Qt.Horizontal, 'Traced')
        self.trace_list.setModel(self.trace_list_model)

        self.trace_list.doubleClicked.connect(self.trace_list_double_click)

        self.class_list = DwarfListView()
        self.class_list_model = QtGui.QStandardItemModel(0, 1)
        self.class_list_model.setHeaderData(0, QtCore.Qt.Horizontal, 'Classes')
        self.class_list.setModel(self.class_list_model)

        self.class_list.setContextMenuPolicy(QtCore.Qt.CustomContextMenu)
        self.class_list.customContextMenuRequested.connect(
            self.show_class_list_menu)
        self.class_list.doubleClicked.connect(self.class_list_double_click)

        self.current_class_search = ''

        self.setup_splitter.addWidget(self.trace_list)
        self.setup_splitter.addWidget(self.class_list)

        layout.addWidget(self.setup_splitter)
        layout.addWidget(self.events_list)

        self.setLayout(layout)

    def class_list_double_click(self, model_index):
        class_name = self.class_list_model.item(model_index.row(), 0).text()
        if class_name:
            for i in range(self.trace_list_model.rowCount()):
                if self.trace_list_model.item(i, 0).text() == class_name:
                    return

            self.trace_list_model.appendRow([QtGui.QStandardItem(class_name)])
            self.trace_list_model.sort(0, QtCore.Qt.AscendingOrder)

    def on_enumeration_start(self):
        self.class_list.clear()

    def on_enumeration_match(self, java_class):
        self.class_list_model.appendRow([QtGui.QStandardItem(java_class)])

        if java_class in self._prefixed_classes:
            for i in range(self.trace_list_model.rowCount()):
                if self.trace_list_model.item(i, 0).text() == java_class:
                    return

            self.trace_list_model.appendRow(QtGui.QStandardItem(java_class))

    def on_enumeration_complete(self):
        self.class_list_model.sort(0, QtCore.Qt.AscendingOrder)
        self.trace_list_model.sort(0, QtCore.Qt.AscendingOrder)

    def on_event(self, data):
        trace, event, clazz, data = data
        if trace == 'java_trace':
            self.events_list.add_event(
                {
                    'event': event,
                    'class': clazz,
                    'data': data.replace(',', ', ')
                }
            )
            self._entries_lbl.setText('Events: %d' %
                                      len(self.events_list.data))

    def pause_trace(self):
        self.app.dwarf.dwarf_api('stopJavaTracer')
        self.tracing = False

    def show_class_list_menu(self, pos):
        menu = QtWidgets.QMenu()
        search = menu.addAction('Search')
        action = menu.exec_(self.class_list.mapToGlobal(pos))
        if action:
            if action == search:
                self.class_list._on_cm_search()

    def start_trace(self):
        trace_classes = []
        for i in range(self.trace_list_model.rowCount()):
            trace_classes.append(self.trace_list_model.item(i, 0).text())

        if not trace_classes:
            return

        self.app.dwarf.dwarf_api('startJavaTracer', [trace_classes])
        self.trace_depth = 0
        self.tracing = True
        self.setup_splitter.setVisible(False)
        self.events_list.setVisible(True)

    def stop_trace(self):
        self.app.dwarf.dwarf_api('stopJavaTracer')
        self.tracing = False
        self.setup_splitter.setVisible(True)
        self.events_list.setVisible(False)
        self.events_list.clear()

    def trace_list_double_click(self, model_index):
        self.trace_list_model.removeRow(model_index.row())

    def keyPressEvent(self, event):
        if event.modifiers() & QtCore.Qt.ControlModifier:
            if event.key() == QtCore.Qt.Key_F:
                self.search()
        super(JavaTracePanel, self).keyPressEvent(event)
