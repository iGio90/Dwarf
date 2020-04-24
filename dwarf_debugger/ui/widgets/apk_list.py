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
import os

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QDir
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QPushButton,
                             QFileDialog, QLineEdit, QHeaderView)

from dwarf_debugger.lib.adb import Adb
from dwarf_debugger.ui.dialogs.dwarf_dialog import DwarfDialog
from dwarf_debugger.ui.widgets.list_view import DwarfListView


class ApkListDialog(DwarfDialog):
    """ Dialog that shows installed apks and allows install
    """

    onApkSelected = pyqtSignal(list, name='onApkSelected')

    def __init__(self, parent=None, show_paths=True, show_install=False):
        super(ApkListDialog, self).__init__(parent=parent)
        self.title = 'Packages'

        v_box = QVBoxLayout()
        if show_install:
            h_box = QHBoxLayout()
            self.file_path = QLineEdit()
            self.file_path.setPlaceholderText('Path to apkfile for install')
            h_box.addWidget(self.file_path)
            self.install_button = QPushButton('Install')
            self.install_button.clicked.connect(self._on_install)
            h_box.addWidget(self.install_button)
            v_box.addLayout(h_box)

        self.apklist = ApkList(parent, show_paths)
        self.apklist.retrieve_thread.onFinished.connect(self._on_finished)
        self.apklist.onApkSelected.connect(self._on_apkselected)
        self.refresh_button = QPushButton('Refresh')
        self.refresh_button.clicked.connect(self._on_refresh)
        v_box.addWidget(self.apklist)
        v_box.addWidget(self.refresh_button)
        self.setLayout(v_box)

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    def _on_install(self):
        if not self.file_path.text():
            file_path = QFileDialog.getOpenFileName(
                self, 'Select an apk to install', QDir.currentPath(), '*.apk')
            self.file_path.setText(file_path)

        if os.path.exists(self.file_path.text()):
            self.apklist.adb.install(file_path)

    def _on_refresh(self):
        self.refresh_button.setEnabled(False)
        self.apklist.refresh()

    def _on_finished(self):
        self.refresh_button.setEnabled(True)

    def _on_apkselected(self, data):
        self.close()
        self.onApkSelected.emit(data)


class PackageRetrieveThread(QThread):
    """ Thread to retrieve installed packes via adb
    """
    onAddPackage = pyqtSignal(list, name='onAddPackage')
    onFinished = pyqtSignal(name='onFinished')
    onError = pyqtSignal(str, name='onError')

    def __init__(self, adb, parent=None):
        super(PackageRetrieveThread, self).__init__(parent=parent)
        self.adb = adb

        if not self.adb.available():
            return

    def run(self):
        """run
        """
        if self.adb.available():
            packages = self.adb.list_packages()
            for package in sorted(packages, key=lambda x: x.package):
                self.onAddPackage.emit([package.package, package.path])

        self.onFinished.emit()


class ApkList(DwarfListView):
    """ Displays installed APKs
    """

    onApkSelected = pyqtSignal(list, name='onApkSelected')

    def __init__(self, parent=None, show_path=True):
        super(ApkList, self).__init__(parent=parent)

        self.adb = Adb()
        self.adb.device = parent.dwarf.device.id

        if not self.adb.available():
            return

        self.retrieve_thread = PackageRetrieveThread(self.adb)
        if self.retrieve_thread is not None:
            self.retrieve_thread.onAddPackage.connect(self._on_addpackage)

        if show_path:
            self.apk_model = QStandardItemModel(0, 2)
        else:
            self.apk_model = QStandardItemModel(0, 1)

        self.apk_model.setHeaderData(0, Qt.Horizontal, 'Name')

        if show_path:
            self.apk_model.setHeaderData(1, Qt.Horizontal, 'Path')

        self.setModel(self.apk_model)
        self.header().setSectionResizeMode(0, QHeaderView.ResizeToContents)

        self.doubleClicked.connect(self._on_apk_selected)

        if self.retrieve_thread is not None:
            if not self.retrieve_thread.isRunning():
                self.retrieve_thread.start()

    # ************************************************************************
    # **************************** Functions *********************************
    # ************************************************************************
    def refresh(self):
        """ Refresh Packages
        """
        if self.retrieve_thread is not None:
            if not self.retrieve_thread.isRunning():
                self.clear()
                self.retrieve_thread.start()

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    def _on_addpackage(self, package):
        if package:
            name = QStandardItem()
            name.setText(package[0])

            if self.apk_model.columnCount() == 2:
                path = QStandardItem()
                path.setText(package[1])

                self.apk_model.appendRow([name, path])
            else:
                self.apk_model.appendRow([name])

    def _on_apk_selected(self, model_index):
        item = self.apk_model.itemFromIndex(model_index).row()
        if item != -1:
            package = self.apk_model.item(item, 0).text()
            if self.apk_model.columnCount() == 2:
                path = self.apk_model.item(item, 1).text()
                self.onApkSelected.emit([package, path])
            else:
                self.onApkSelected.emit([package, None])
