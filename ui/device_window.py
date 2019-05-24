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
import os
import lzma
import frida
import requests

from PyQt5.QtCore import Qt, QSize, QRect, pyqtSignal, QThread, QMargins, QTimer
from PyQt5.QtGui import QFont, QPixmap, QIcon
from PyQt5.QtWidgets import (QWidget, QDialog, QLabel, QVBoxLayout, QHBoxLayout, QPushButton, QListView, 
    QSpacerItem, QSizePolicy, QStyle, qApp, QComboBox, QFormLayout, QLineEdit)

from ui.dialog_js_editor import JsEditorDialog
from ui.list_pick import PickList

from ui.widgets.device_bar import DeviceBar
from ui.process_list import ProcessList
from ui.spawns_list import SpawnsList

from lib import utils

class DeviceWindow(QDialog):

    onSelectedProcess = pyqtSignal(list, name='onSelectedProcess')
    onSpwanSelected = pyqtSignal(list, name='onSpawnSelected')
    onClosed = pyqtSignal(name='onClosed')

    def __init__(self, parent=None, device='local'):
        super(DeviceWindow, self).__init__(parent=parent)
        self.setSizeGripEnabled(False)
        self.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)
        self.setWindowFlag(Qt.WindowCloseButtonHint, True)
        self.setModal(True)

        self.device_type = device

        try:
            if device == 'local':
                self.device = frida.get_local_device()
                self.setWindowTitle('Dwarf - Local Session')
            elif device == 'usb':
                self.setWindowTitle('Dwarf - USB Session')
                #self.device = frida.get_usb_device()
                self.device = None
            else:
                self.device = frida.get_local_device()
        except frida.TimedOutError:
            self.device = None
            print('Frida TimedOutError: No Device')

        self.updated_frida_version = ''
        self.updated_frida_assets_url = {}

        self.frida_update_thread = None
        self.devices_thread = None

        self.setup_ui()

    def closeEvent(self, event):
        super(DeviceWindow, self).closeEvent(event)
        self.onClosed.emit()

    def _update_device(self, device_id):
        try:
            self.device = frida.get_device(device_id)
            self.proc_list.device = self.device
            self.spawn_list.device = self.device
        except frida.TimedOutError:
            self.device = None

    def setup_ui(self):
        self.setFixedSize(800, 400)

        main_wrap = QVBoxLayout(self)
        main_wrap.setContentsMargins(0, 0, 0, 0)

        self._dev_bar = DeviceBar(self, self.device_type)
        self._dev_bar.onDeviceUpdated.connect(self._update_device)
        # not needed on local
        #if self.device and self.device.type == 'local':
            #self._dev_bar.setVisible(False)

        main_wrap.addWidget(self._dev_bar)

        """frm_lyt = QFormLayout()
        frm_lyt.setContentsMargins(10, 10, 10, 10)

        _label = QLabel('Script to load (optional)')
        frm_lyt.addRow(_label)

        user_script_path = QLineEdit()
        load_button = QPushButton('...')

        frm_lyt.addRow(load_button, user_script_path)

        main_wrap.addLayout(frm_lyt)"""

        # procs/spawns lists
        spawns_vbox = QVBoxLayout()

        spawns_label = QLabel('SPAWN')
        spawns_label.setFont(QFont('Anton', 20, QFont.Normal))
        spawns_vbox.addWidget(spawns_label)
        self.spawn_list = SpawnsList(device=self.device)
        self.spawn_list.onProcessSelected.connect(self._spawn_selected)
        spawns_vbox.addWidget(self.spawn_list)

        procs_vbox = QVBoxLayout()
        procs_label = QLabel('PROCS')
        procs_label.setFont(QFont('Anton', 20, QFont.Normal))
        procs_vbox.addWidget(procs_label)

        self.proc_list = ProcessList(device=self.device)
        self.proc_list.onProcessSelected.connect(self._pid_selected)
        procs_vbox.addWidget(self.proc_list)

        inner_hbox = QHBoxLayout()
        inner_hbox.setContentsMargins(10, 10, 10, 10)
        inner_hbox.addLayout(spawns_vbox)
        inner_hbox.addLayout(procs_vbox)

        vbox = QVBoxLayout()
        vbox.setContentsMargins(0, 0, 0, 0)
        #vbox.addWidget(self._dev_bar)
        main_wrap.addLayout(inner_hbox)

        #self.setLayout(vbox)
        # center
        self.setGeometry(QStyle.alignedRect(Qt.LeftToRight, Qt.AlignCenter, self.size(), qApp.desktop().availableGeometry()))

    def _pid_selected(self, pid):
        if pid:
            self.accept()
            self.onSelectedProcess.emit([self.device, pid])

    def _spawn_selected(self, spawn):
        if spawn[1]:
            self.accept()
            self.onSpwanSelected.emit([self.device, spawn[1]])
