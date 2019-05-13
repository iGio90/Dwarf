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
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QWidget, QLineEdit, QVBoxLayout, QHBoxLayout, QRadioButton, QPushButton, QProgressDialog, \
    QSizePolicy, QApplication

from ui.list_view import DwarfListView
from lib import utils
from ui.hex_edit import HighLight, HighlightExistsError

class SearchThread(QThread):

    onCmdCompleted = pyqtSignal(str, name='onCmdCompleted')
    onError = pyqtSignal(str, name='onError')

    dwarf = None
    ranges = []
    pattern = ''

    def __init__(self, dwarf=None, parent=None):
        super().__init__(parent=parent)
        self.dwarf = dwarf

    def run(self):
        if self.dwarf is None:
            self.onError.emit('Dwarf missing')
            return
        if self.pattern is '' or len(self.pattern) <= 0:
            self.onError.emit('Pattern missing')
            return
        if len(self.ranges) <= 0:
            self.onError.emit('Ranges missing')
            return

        for r in self.ranges:
            self.dwarf.search(r[0], r[1], self.pattern)

        self.onCmdCompleted.emit('finished')

    


class SearchPanel(QWidget):
    """ SearchPanel
    """

    onShowMemoryRequest = pyqtSignal(str, name='onShowMemoryRequest')

    def __init__(self, parent=None, show_progress_dlg=False):
        super(SearchPanel, self).__init__(parent=parent)
        self._app_window = parent

        if self._app_window.dwarf is None:
            print('SearchPanel created before Dwarf exists')
            return

        self._app_window.dwarf.onMemoryScanResult.connect(self._on_search_result)

        self._ranges_model = None
        self._result_model = None

        self._blocking_search = show_progress_dlg
        self.progress = None
        self._pattern_length = 0

        box = QVBoxLayout()

        self.input = QLineEdit()
        self.input.setPlaceholderText('search for a sequence of bytes in hex format: deadbeef123456aabbccddeeff...')
        box.addWidget(self.input)

        self.check_all_btn = QPushButton('check all')
        self.check_all_btn.clicked.connect(self._on_click_check_all)
        self.uncheck_all_btn = QPushButton('uncheck all')
        self.uncheck_all_btn.clicked.connect(self._on_click_uncheck_all)
        self.search_btn = QPushButton('search')
        self.search_btn.clicked.connect(self._on_click_search)

        h_box = QHBoxLayout()
        h_box.addWidget(self.check_all_btn)
        h_box.addWidget(self.uncheck_all_btn)
        h_box.addWidget(self.search_btn)
        box.addLayout(h_box)

        self.ranges = DwarfListView(self)
        self.results = DwarfListView(self)

        h_box = QHBoxLayout()
        h_box.addWidget(self.ranges)
        h_box.addWidget(self.results)
        box.addLayout(h_box)

        self.setLayout(box)

        self._setup_models()

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************
    def _setup_models(self):
        self._ranges_model = QStandardItemModel(0, 6)

        # just replicate ranges panel model
        self._ranges_model.setHeaderData(0, Qt.Horizontal, 'Address')
        self._ranges_model.setHeaderData(0, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self._ranges_model.setHeaderData(1, Qt.Horizontal, 'Size')
        self._ranges_model.setHeaderData(1, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self._ranges_model.setHeaderData(2, Qt.Horizontal, 'Protection')
        self._ranges_model.setHeaderData(2, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self._ranges_model.setHeaderData(3, Qt.Horizontal, 'FileOffset')
        self._ranges_model.setHeaderData(3, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self._ranges_model.setHeaderData(4, Qt.Horizontal, 'FileSize')
        self._ranges_model.setHeaderData(4, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self._ranges_model.setHeaderData(5, Qt.Horizontal, 'FilePath')

        # add all the ranges from the ranges panel
        for i in range(self._app_window.ranges_panel._ranges_model.rowCount()):
            addr = QStandardItem(self._app_window.ranges_panel._ranges_model.item(i, 0).text())
            addr.setCheckable(True)

            size = QStandardItem(self._app_window.ranges_panel._ranges_model.item(i, 1).text())
            protection = QStandardItem(self._app_window.ranges_panel._ranges_model.item(i, 2).text())
            file_addr = self._app_window.ranges_panel._ranges_model.item(i, 3)
            if file_addr is not None:
                file_addr = QStandardItem(file_addr.text())
            file_size = self._app_window.ranges_panel._ranges_model.item(i, 4)
            if file_size is not None:
                file_size = QStandardItem(file_size.text())
            file_path = self._app_window.ranges_panel._ranges_model.item(i, 5)
            if file_path is not None:
                file_path = QStandardItem(file_path.text())
            self._ranges_model.appendRow(
                [addr, size, protection, file_addr, file_size, file_path])

        self.ranges.setModel(self._ranges_model)

        # setup results model
        self._result_model = QStandardItemModel(0, 1)
        self._result_model.setHeaderData(0, Qt.Horizontal, 'Address')
        self.results.setModel(self._result_model)
        self.results.doubleClicked.connect(self._on_dblclicked)

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    def _on_click_check_all(self):
        for i in range(self._ranges_model.rowCount()):
            self._ranges_model.item(i, 0).setCheckState(Qt.Checked)

    def _on_click_uncheck_all(self):
        for i in range(self._ranges_model.rowCount()):
            self._ranges_model.item(i, 0).setCheckState(Qt.Unchecked)

    def _on_dblclicked(self, model_index):
        item = self._result_model.itemFromIndex(model_index)
        if item:
            self.onShowMemoryRequest.emit(
                self._result_model.item(model_index.row(), 0).text())

    def _on_click_search(self):
        pattern = self.input.text().replace(' ', '')
        if pattern == '':
            return 1

        ranges = []
        for i in range(self._ranges_model.rowCount()):
            item = self._ranges_model.item(i, 0)
            if item.checkState() == Qt.Checked:
                size = self._ranges_model.item(i, 1)
                ranges.append([item.text(), size.text()])

        if len(ranges) == 0:
            return 1

        if self._blocking_search:
            self.progress = QProgressDialog()
            self.progress.setFixedSize(300, 50)
            self.progress.setAutoFillBackground(True)
            self.progress.setWindowModality(Qt.WindowModal)
            self.progress.setWindowTitle('Please wait')
            self.progress.setLabelText('searching...')
            self.progress.setSizeGripEnabled(False)
            self.progress.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            self.progress.setWindowFlag(Qt.WindowContextHelpButtonHint, False)
            self.progress.setWindowFlag(Qt.WindowCloseButtonHint, False)
            self.progress.setModal(True)
            self.progress.setCancelButton(None)
            self.progress.setRange(0, 0)
            self.progress.setMinimumDuration(0)
            self.progress.forceShow()
        
        self._app_window.show_progress('searching...')
        self.input.setEnabled(False)
        self.search_btn.setEnabled(False)
        self.check_all_btn.setEnabled(False)
        self.uncheck_all_btn.setEnabled(False)

        self._pattern_length = len(pattern) * .5
        
        search_thread = SearchThread(self._app_window.dwarf, self)
        search_thread.onCmdCompleted.connect(self._on_search_complete)
        search_thread.onError.connect(self._on_search_error)
        search_thread.pattern = pattern
        search_thread.ranges = ranges
        search_thread.start()

        
    def _on_search_result(self, data):
        if data is not None:
            for o in data:
                addr = o['address']
                if self.results._uppercase_hex:
                    addr = addr.upper().replace('0X', '0x')
                self._result_model.appendRow(QStandardItem(addr))

                if self._app_window.memory_panel:
                    try:
                        self._app_window.memory_panel.add_highlight(HighLight('search', utils.parse_ptr(addr), self._pattern_length))
                    except HighlightExistsError:
                        pass


    def _on_search_complete(self):
        self.input.setEnabled(True)
        self.search_btn.setEnabled(True)
        self.check_all_btn.setEnabled(True)
        self.uncheck_all_btn.setEnabled(True)
        self._app_window.hide_progress()
        self._app_window.set_status_text('Search complete: {0} matches'.format(self._result_model.rowCount()))
        if self._blocking_search:
            self.progress.cancel()

    def _on_search_error(self, msg):
        utils.show_message_box(msg)
