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
from PyQt5.QtCore import Qt, QSortFilterProxyModel
from PyQt5.QtGui import QStandardItem
from PyQt5.QtWidgets import QTreeView, QHeaderView

from dwarf_debugger.lib.prefs import Prefs


class DwarfListView(QTreeView):
    """ Using QTreeView as ListView because it allows ListView+QHeaderView
    """

    def __init__(self, parent=None, search_enabled=True):
        super(DwarfListView, self).__init__(parent=parent)

        self._search_enabled = search_enabled
        self._current_search = ''

        self._uppercase_hex = True

        _prefs = Prefs()
        self.rows_dualcolor = _prefs.get('dwarf_ui_alternaterowcolors', False)
        self.uppercase_hex = _prefs.get(
            'dwarf_ui_hexstyle', 'upper').lower() == 'upper'

        self.setEditTriggers(self.NoEditTriggers)
        self.setHeaderHidden(False)
        self.setAutoFillBackground(True)
        self.setRootIsDecorated(False)
        # TODO: use filter
        self._proxy_model = QSortFilterProxyModel(self)
        self._proxy_model.setSourceModel(self.model())
        # self.setSortingEnabled(True)

    def keyPressEvent(self, event):
        """ onkeydown
        """
        key = event.key()
        mod = event.modifiers()
        if key == Qt.Key_F and mod & Qt.ControlModifier and self.search_enabled:  # CTRL + F
            self._on_cm_search()
        else:
            super(DwarfListView, self).keyPressEvent(event)

    # ************************************************************************
    # **************************** Properties ********************************
    # ************************************************************************
    @property
    def rows_dualcolor(self):
        """ AlternatingRowColors
        """
        return self.alternatingRowColors()

    @rows_dualcolor.setter
    def rows_dualcolor(self, value):
        """ AlternatingRowColors
        """
        if isinstance(value, bool):
            self.setAlternatingRowColors(value)
        elif isinstance(value, str):
            self.setAlternatingRowColors(value.lower() == 'true')

    @property
    def uppercase_hex(self):
        """ Addresses displayed lower/upper-case
        """
        return self._uppercase_hex

    @uppercase_hex.setter
    def uppercase_hex(self, value):
        """ Addresses displayed lower/upper-case
            value - bool or str
                    'upper', 'lower'
        """
        if isinstance(value, bool):
            self._uppercase_hex = value
        elif isinstance(value, str):
            self._uppercase_hex = (value == 'upper')

    @property
    def search_enabled(self):
        return self._search_enabled

    @search_enabled.setter
    def search_enabled(self, value):
        if isinstance(value, bool):
            self._search_enabled = value

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************
    def clear(self):
        """ Delete Entries but not Headerdata
        """
        model = self.model()
        if model is not None:
            model.removeRows(0, model.rowCount())

    def get_item(self, index):
        """ Returns [] with col_texts
        """
        if self.model() is not None:
            item_data = []
            if index < self.model().rowCount():
                for i in range(self.model().columnCount()):
                    item_text = self.model().item(index, i).text()
                    if item_text:
                        item_data.append(item_text)
                    else:
                        item_data.append('')

                return item_data

        return None

    def get_item_text(self, index, col):
        """ returns text in index, col
        """
        if self.model() is not None:
            if index < self.model().rowCount():
                if col < self.model().columnCount():
                    item = self.model().item(index, col)
                    if isinstance(item, QStandardItem):
                        return self.model().item(index, col).text()

        return None

    def contains_text(self, text, case_sensitive=False, stop_at_match=True, match_exactly=False):
        """ looks in all fields for text
            returns true, [[row, col]] if text exists
        """
        if not text:
            return

        ret_val = False
        ret_res = []
        if self.model() is not None:
            for i in range(self.model().rowCount()):
                for j in range(self.model().columnCount()):
                    item_text = self.get_item_text(i, j)
                    if item_text is None:
                        continue

                    if match_exactly:
                        if not case_sensitive:
                            _eval = item_text.lower() == text.lower()
                        else:
                            _eval = item_text == text
                    else:
                        if not case_sensitive:
                            _eval = text.lower() in item_text.lower()
                        else:
                            _eval = item_text in text

                    if _eval:
                        ret_res.append([i, j])
                        if stop_at_match:
                            break
        if ret_res:
            ret_val = True

        if ret_val:
            return ret_val, ret_res
        else:
            return ret_val, []

    def number_of_items(self):
        """ returns number of rows
        """
        if self.model() is not None:
            return self.model().rowCount()

        return None

    def number_of_rows(self):
        """ returns number of rows
        """
        if self.model() is not None:
            return self.number_of_items()

        return None

    def number_of_total(self):
        """ returns number of all fields rows+cols
        """
        if self.model() is not None:
            return self.model().rowCount() + self.model().columnCount()

        return None

    def number_of_cols(self):
        """ returns number of cols
        """
        if self.model() is not None:
            return self.model().columnCount()

        return None

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    def mouseDoubleClickEvent(self, event):  # pylint: disable=invalid-name
        """ override doubleclickevent to prevent doublerightclicks
        """
        if event.button() == Qt.LeftButton:
            super().mouseDoubleClickEvent(event)

    def resizeEvent(self, event):  # pylint: disable=invalid-name
        """ override to give user control over header back
        """
        super(DwarfListView, self).resizeEvent(event)
        header = self.header()
        resize_mode = (QHeaderView.ResizeToContents | QHeaderView.Interactive)
        if header:
            for col in range(header.count()):
                if header.sectionResizeMode(col) == resize_mode:
                    header.setSectionResizeMode(
                        col, QHeaderView.ResizeToContents)
                    width = header.sectionSize(col)
                    header.setSectionResizeMode(col, QHeaderView.Interactive)
                    header.resizeSection(col, width)

    def _on_cm_search(self):
        from dwarf_debugger.ui.dialogs.dialog_input import InputDialog
        accept, input_ = InputDialog.input(
            self, hint='Search something in this list', placeholder='search...', input_content=self._current_search)

        if accept and not input_:
            # reset search
            self._current_search = ''
            for row in range(self.model().rowCount()):
                self.setRowHidden(
                    row, self.model().invisibleRootItem().index(), False)
        elif accept and input_:
            # search for input
            self._current_search = input_

            have_result, search_results = self.contains_text(
                input_, stop_at_match=False)

            if not have_result:
                return

            # hide non matching
            for row in range(self.model().rowCount()):
                item = self.model().item(row, 0)
                hide = True
                for sr in search_results:
                    if sr[0] == row:
                        hide = False
                        break

                self.setRowHidden(
                    row, self.model().invisibleRootItem().index(), hide)
