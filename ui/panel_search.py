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
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QModelIndex
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QWidget, QLineEdit, QVBoxLayout, QHBoxLayout, QRadioButton, QPushButton, QProgressDialog, \
    QSizePolicy, QApplication, QHeaderView

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

        #_list = []
        for r in self.ranges:
            self.dwarf.search(r[0], int(r[1].replace(',', '')), self.pattern)
            #_list.append({'start': r[0], 'size': int(r[1].replace(',', ''))})

        #self.dwarf.search_list(_list, self.pattern)
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

        self._search_results = []

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
        self.ranges.clicked.connect(self._on_show_results)
        self.results = DwarfListView(self)
        self.results.setVisible(False)

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
        self._ranges_model = QStandardItemModel(0, 7)

        # just replicate ranges panel model
        self._ranges_model.setHeaderData(0, Qt.Horizontal, 'x') # TODO: replace with checkbox in header - remove checkall btns
        self._ranges_model.setHeaderData(0, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self._ranges_model.setHeaderData(1, Qt.Horizontal, 'Address')
        self._ranges_model.setHeaderData(1, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self._ranges_model.setHeaderData(2, Qt.Horizontal, 'Size')
        self._ranges_model.setHeaderData(2, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self._ranges_model.setHeaderData(3, Qt.Horizontal, 'Protection')
        self._ranges_model.setHeaderData(3, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self._ranges_model.setHeaderData(4, Qt.Horizontal, 'FileOffset')
        self._ranges_model.setHeaderData(4, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self._ranges_model.setHeaderData(5, Qt.Horizontal, 'FileSize')
        self._ranges_model.setHeaderData(5, Qt.Horizontal, Qt.AlignCenter,
                                         Qt.TextAlignmentRole)
        self._ranges_model.setHeaderData(6, Qt.Horizontal, 'FilePath')

        self.ranges.setModel(self._ranges_model)
        self.ranges.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.ranges.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.ranges.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.ranges.header().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.ranges.header().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.ranges.header().setSectionResizeMode(5, QHeaderView.ResizeToContents)

        self.ranges.doubleClicked.connect(self._on_range_dblclick)

        # setup results model
        self._result_model = QStandardItemModel(0, 1)
        self._result_model.setHeaderData(0, Qt.Horizontal, 'Address')
        self.results.setModel(self._result_model)
        self.results.doubleClicked.connect(self._on_dblclicked)

    def set_ranges(self, ranges):
        """ Fills Rangelist with Data
        """
        self.ranges.header().setSectionResizeMode(0, QHeaderView.Fixed)
        if isinstance(ranges, list):
            self._ranges_model.removeRows(0, self._ranges_model.rowCount())
            for range_entry in ranges:
                if 'protection' in range_entry and isinstance(range_entry['protection'], str):
                    if 'r' not in range_entry['protection']:
                        # skip not readable range
                        continue

                else:
                    continue
                # create items to add
                str_frmt = ''
                if self.ranges._uppercase_hex:
                    str_frmt = '0x{0:X}'
                else:
                    str_frmt = '0x{0:x}'

                addr = QStandardItem()
                addr.setTextAlignment(Qt.AlignCenter)
                addr.setText(str_frmt.format(int(range_entry['base'], 16)))

                size = QStandardItem()
                size.setTextAlignment(Qt.AlignRight)
                size.setText("{0:,d}".format(int(range_entry['size'])))

                protection = QStandardItem()
                protection.setTextAlignment(Qt.AlignCenter)
                protection.setText(range_entry['protection'])

                file_path = None
                file_addr = None
                file_size = None

                if len(range_entry) > 3:
                    if range_entry['file']['path']:
                        file_path = QStandardItem()
                        file_path.setText(range_entry['file']['path'])

                    if range_entry['file']['offset']:
                        file_addr = QStandardItem()
                        file_addr.setTextAlignment(Qt.AlignCenter)
                        file_addr.setText(
                            str_frmt.format(range_entry['file']['offset']))

                    if range_entry['file']['size']:
                        file_size = QStandardItem()
                        file_size.setTextAlignment(Qt.AlignRight)
                        file_size.setText("{0:,d}".format(
                            int(range_entry['file']['size'])))


                checkbox = QStandardItem()
                checkbox.setCheckable(True)

                self._ranges_model.appendRow(
                    [checkbox, addr, size, protection, file_addr, file_size, file_path])

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    def _on_range_dblclick(self, model_index):
        item = self._ranges_model.itemFromIndex(model_index)
        if item:
            if self._ranges_model.item(model_index.row(), 0).checkState() != Qt.Checked:
                self._ranges_model.item(model_index.row(), 0).setCheckState(Qt.Checked)
            else:
                self._ranges_model.item(model_index.row(), 0).setCheckState(Qt.Unchecked)

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
        self._search_results = []
        for i in range(self._ranges_model.rowCount()):
            item = self._ranges_model.item(i, 0)
            if item.checkState() == Qt.Checked:
                addr = self._ranges_model.item(i, 1)
                size = self._ranges_model.item(i, 2)
                ranges.append([addr.text(), size.text()])

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
        self._search_results.append(data)

    def _on_search_complete(self):
        self.input.setEnabled(True)
        self.search_btn.setEnabled(True)
        self.check_all_btn.setEnabled(True)
        self.uncheck_all_btn.setEnabled(True)
        self._app_window.hide_progress()
        if self._blocking_search:
            self.progress.cancel()

        self._ranges_model.removeColumns(4, 3)
        self._ranges_model.setHeaderData(3, Qt.Horizontal, 'Search Results')
        self._ranges_model.setHeaderData(3, Qt.Horizontal, None, Qt.TextAlignmentRole)

        results_count = 0
        is_selected = False
        for i in range(self._ranges_model.rowCount()):
            item = self._ranges_model.item(i, 0)
            if item.checkState() == Qt.Checked:
                item.setCheckState(Qt.Unchecked)
                if not is_selected:
                    is_selected = True
                    self.ranges.setCurrentIndex(self._ranges_model.index(i, 0))
            else:
                self._search_results.insert(i, None)
                self._ranges_model.item(i, 3).setText('')
                self._ranges_model.item(i, 3).setTextAlignment(Qt.AlignLeft)
                continue

            if len(self._search_results[i]):
                results_count += len(self._search_results[i])
                self._ranges_model.item(i, 3).setText('Matches: {0}'.format(len(self._search_results[i])))
                self._ranges_model.item(i, 3).setTextAlignment(Qt.AlignLeft)
            else:
                self._ranges_model.item(i, 3).setText('')
                self._ranges_model.item(i, 3).setTextAlignment(Qt.AlignLeft)

        self._app_window.set_status_text('Search complete: {0} matches'.format(results_count))
        if results_count:
            for i in self._search_results:
                if i and len(i):
                    self.results.setVisible(True)
                    for result in i:
                        self._result_model.appendRow(QStandardItem(result['address']))

                    break

    def _on_search_error(self, msg):
        utils.show_message_box(msg)

    def _on_show_results(self):
        if self._search_results:
            self.results.clear()
            if self._app_window.memory_panel:
                self._app_window.memory_panel.remove_highlights('search')
            selected_index = self.ranges.selectionModel().currentIndex().row()
            if selected_index is not None:
                item_txt = self._ranges_model.item(selected_index, 3).text()
                if item_txt == '':
                    return

                for result in self._search_results[selected_index]:
                    self._result_model.appendRow(QStandardItem(result['address']))

                    # TODO: fix hexview highlights performance
                    """
                    if self._app_window.memory_panel:
                        try:
                            self._app_window.memory_panel.add_highlight(
                                HighLight('search', utils.parse_ptr(result['address']), self._pattern_length))
                        except HighlightExistsError:
                            pass"""
