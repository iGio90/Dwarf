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
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QWidget, QLineEdit, QVBoxLayout, QHBoxLayout, QRadioButton, QPushButton, QProgressDialog, \
    QSizePolicy

from ui.list_view import DwarfListView


class SearchPanel(QWidget):
    """ SearchPanel
    """

    def __init__(self, parent=None):
        super(SearchPanel, self).__init__(parent=parent)
        self._app_window = parent

        if self._app_window.dwarf is None:
            print('SearchPanel created before Dwarf exists')
            return

        self._ranges_model = None
        self._result_model = None

        box = QVBoxLayout()

        self.input = QLineEdit()
        self.input.setPlaceholderText('search for a sequence of bytes in hex format: deadbeef123456aabbccddeeff...')
        box.addWidget(self.input)

        check_all = QPushButton('check all')
        check_all.clicked.connect(self._on_click_check_all)
        uncheck_all = QPushButton('uncheck all')
        uncheck_all.clicked.connect(self._on_click_uncheck_all)
        search = QPushButton('search')
        search.clicked.connect(self._on_click_search)

        h_box = QHBoxLayout()
        h_box.addWidget(check_all)
        h_box.addWidget(uncheck_all)
        h_box.addWidget(search)
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

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    def _on_click_check_all(self):
        for i in range(self._ranges_model.rowCount()):
            self._ranges_model.item(i, 0).setCheckState(Qt.Checked)

    def _on_click_uncheck_all(self):
        for i in range(self._ranges_model.rowCount()):
            self._ranges_model.item(i, 0).setCheckState(Qt.Unchecked)

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

        progress = QProgressDialog()
        progress.setFixedSize(300, 50)
        progress.setAutoFillBackground(True)
        progress.setWindowModality(Qt.WindowModal)
        progress.setWindowTitle('Please wait')
        progress.setLabelText('searching...')
        progress.setSizeGripEnabled(False)
        progress.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        progress.setWindowFlag(Qt.WindowContextHelpButtonHint, False)
        progress.setWindowFlag(Qt.WindowCloseButtonHint, False)
        progress.setModal(True)
        progress.setCancelButton(None)
        progress.setRange(0, 0)
        progress.setMinimumDuration(0)
        progress.forceShow()

        for r in ranges:
            res = self._app_window.dwarf.search(r[0], r[1], pattern)
            if res is not None:
                for o in res:
                    self._result_model.appendRow(QStandardItem(o['address']))

        progress.cancel()
