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

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (QDialog, qApp, QStyle)


class DwarfDialog(QDialog):
    """ DwarfDialog
    """

    def __init__(self, parent=None):
        super().__init__(parent=parent)
        self._title = "Dwarf"
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)
        self.setWindowFlag(Qt.WindowCloseButtonHint, True)

    # ************************************************************************
    # **************************** Properties ********************************
    # ************************************************************************

    @property
    def title(self):
        """ return title
        """
        return self._title

    @title.setter
    def title(self, value):
        """ set title
        """
        if isinstance(value, str):
            self._title = "Dwarf - " + value

    @property
    def modal(self):
        """ return ismodal
        """
        return self.isModal()

    @modal.setter
    def modal(self, value):
        """ set modal
        """
        if isinstance(value, bool):
            self.setModal(value)

    # override show
    def showEvent(self, QShowEvent):  # pylint: disable=invalid-name
        """ center dialog update title
        """
        self.setWindowTitle(self.title)
        self.setGeometry(
            QStyle.alignedRect(Qt.LeftToRight, Qt.AlignCenter, self.size(),
                               qApp.desktop().availableGeometry()))
        return super().showEvent(QShowEvent)
