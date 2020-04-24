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
from PyQt5.QtCore import Qt, pyqtSignal, QRect
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QPainter, QColor, QPixmap, QIcon
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QHeaderView

from dwarf_debugger.lib.git import Git
from dwarf_debugger.lib.scripts_manager import ScriptsManager
from dwarf_debugger.ui.widgets.list_view import DwarfListView


class ScriptsTable(DwarfListView):
    """ ScriptsListView
    """

    onScriptSelected = pyqtSignal(str, name='onScriptSelected')

    def __init__(self, parent=None):
        super(ScriptsTable, self).__init__(parent=parent)

        self._scripts_model = QStandardItemModel(0, 6)
        self._scripts_model.setHeaderData(0, Qt.Horizontal, 'Name')
        self._scripts_model.setHeaderData(1, Qt.Horizontal, 'Author')
        self._scripts_model.setHeaderData(1, Qt.Horizontal, Qt.AlignCenter,
                                          Qt.TextAlignmentRole)
        self._scripts_model.setHeaderData(2, Qt.Horizontal, 'A')
        self._scripts_model.setHeaderData(2, Qt.Horizontal, Qt.AlignCenter,
                                          Qt.TextAlignmentRole)
        self._scripts_model.setHeaderData(3, Qt.Horizontal, 'I')
        self._scripts_model.setHeaderData(3, Qt.Horizontal, Qt.AlignCenter,
                                          Qt.TextAlignmentRole)
        self._scripts_model.setHeaderData(4, Qt.Horizontal, 'W')
        self._scripts_model.setHeaderData(4, Qt.Horizontal, Qt.AlignCenter,
                                          Qt.TextAlignmentRole)
        self._scripts_model.setHeaderData(5, Qt.Horizontal, 'Description')

        self.setModel(self._scripts_model)

        self.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.header().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.header().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.header().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.header().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.doubleClicked.connect(self._item_doubleclicked)

    def _item_doubleclicked(self, item):
        row = item.row()
        script_name = self._scripts_model.item(row, 0).text()
        self.onScriptSelected.emit(script_name)

    def add_item(self, data):
        """ Add Item
        """
        self._scripts_model.appendRow(data)


class ScriptsDialog(QDialog):
    """ Scripts
    """

    def __init__(self, app_window):
        super(ScriptsDialog, self).__init__(app_window)

        self.script = None
        self._app_window = app_window
        self._script_manager = ScriptsManager()
        self._git = Git()

        self.setMinimumWidth(800)

        box = QVBoxLayout()
        self.table = ScriptsTable(self)
        self.table.onScriptSelected.connect(self._item_selected)
        self.table.setMinimumWidth(800)

        # create a centered dot icon
        _section_width = self.table.header().sectionSize(3)
        self._new_pixmap = QPixmap(max(_section_width, 40), 20)
        self._new_pixmap.fill(Qt.transparent)
        painter = QPainter(self._new_pixmap)
        rect = QRect((_section_width * 0.5) - 5, 0, 20, 20)
        painter.setBrush(QColor('#666'))
        painter.setPen(QColor('#666'))
        painter.drawEllipse(rect)
        self._dot_icon = QIcon(self._new_pixmap)

        box.addWidget(self.table)
        lbl = QLabel('OS Support - A: Android I: IOS W: Windows')
        box.addWidget(lbl)
        self.setLayout(box)
        self._init_list()

    def _init_list(self):
        for script_name in sorted(self._script_manager.get_scripts().keys()):
            script = self._script_manager.get_script(script_name)
            info = script['info']

            if 'dwarf' in info:
                continue

            _name = QStandardItem()
            _name.setText(script_name)
            _name.setToolTip(info['name'])

            _author = QStandardItem()
            if 'author' in info:
                _author.setTextAlignment(Qt.AlignCenter)
                _author.setText(info['author'])

            _android = QStandardItem()
            if 'android' in info:
                _android.setIcon(self._dot_icon)

            _ios = QStandardItem()
            if 'ios' in info:
                _ios.setIcon(self._dot_icon)

            _windows = QStandardItem()
            if 'windows' in info:
                _windows.setIcon(self._dot_icon)

            _desc = QStandardItem()
            if 'description' in info:
                _desc.setText(info['description'])

            self.table.add_item(
                [_name, _author, _android, _ios, _windows, _desc])

    def _item_selected(self, script_name):
        script_url = self._script_manager.get_script(script_name)['script']
        script = self._git.get_script(script_url)
        self.script = script
        self.accept()

    @staticmethod
    def pick(app):
        """ helper
        """
        dialog = ScriptsDialog(app)
        result = dialog.exec_()
        return result == QDialog.Accepted, dialog.script
