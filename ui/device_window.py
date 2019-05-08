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
from PyQt5.QtWidgets import QWidget, QDialog, QLabel, QVBoxLayout, QHBoxLayout, QPushButton, QListView, QSpacerItem, QSizePolicy, QStyle, qApp, QComboBox

from lib.adb import Adb
from lib.git import Git
from ui.dialog_js_editor import JsEditorDialog
from ui.list_pick import PickList
from ui.widget_android_package import AndroidPackageWidget
from ui.widget_item_not_editable import NotEditableListWidgetItem

from ui.process_list import ProcessList
from ui.spawns_list import SpawnsList

from lib import utils


class FridaUpdateThread(QThread):
    """ FridaServer Update Thread
        signals:
            on_status_text(str)
            on_finished()
    """
    on_status_text = pyqtSignal(str)
    on_finished = pyqtSignal()
    onError = pyqtSignal(str, name='onError')

    def __init__(self, parent=None):
        super().__init__(parent)
        self.frida_url = ''
        self.adb = None

    def run(self):
        """Runs the UpdateThread
        """

        self.on_status_text.emit('Downloading latest frida')

        try:
            request = requests.get(self.frida_url, stream=True)
        except requests.ConnectionError:
            self.onError.emit('Failed to download latest frida')
            return

        if request is not None and request.status_code == 200:
            with open('frida.xz', 'wb') as frida_archive:
                for chunk in request.iter_content(chunk_size=1024):
                    if chunk:
                        frida_archive.write(chunk)

            self.on_status_text.emit('Extracting latest frida')

            try:
                with lzma.open('frida.xz') as frida_archive:
                    with open('frida', 'wb') as frida_binary:
                        frida_binary.write(frida_archive.read())
                        res = ''
                os.remove('frida.xz')
            except:
                self.onError.emit('Failed to extract frida.xz')
                return

            if not res:
                self.on_status_text.emit('Mounting devices filesystem')
                # mount system rw
                res = self.adb.mount_system()
                if res is None or not res:
                    self.on_status_text.emit('Pushing to device')
                    # push file to device
                    self.adb.push('frida', '/sdcard/')
                    self.on_status_text.emit('Setting up and starting frida')
                    # kill frida
                    self.adb.kill_frida()
                    # copy file note: mv give sometimes a invalid id error
                    self.adb.su_cmd('cp /sdcard/frida /system/xbin/frida')
                    # remove file
                    self.adb.su_cmd('rm /sdcard/frida')
                    # make it executable
                    self.adb.su_cmd('chmod 755 /system/xbin/frida')
                    # start it
                    if not self.adb.start_frida():
                        self.on_status_text('Failed to start frida')

                os.remove('frida')
        else:
            self.onError.emit('Failed to download latest frida')

        self.on_finished.emit()
        self.frida_url = ''


class DevicesUpdateThread(QThread):
    """ Updates DeviceSelector
        signals:
            add_device(devicename, customdata, currentitem)
            devices_updated()
    """
    onAddDevice = pyqtSignal(str, str)
    onDevicesUpdated = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)

    def run(self):
        # get frida devices
        devices = frida.enumerate_devices()

        for device in devices:
            self.onAddDevice.emit(device.name, device.type)

        self.onDevicesUpdated.emit()


class DeviceBar(QWidget):

    onDeviceUpdated = pyqtSignal()

    def __init__(self, parent=None, device_type='usb'):
        super().__init__(parent=parent)
        if device_type == 'local':
            return
        self.parent = parent
        self.wait_for_devtype = device_type
        self.is_waiting = True
        self._adb = Adb()
        self._git = Git()
        self.setAutoFillBackground(True)
        self.setStyleSheet('background-color: crimson; color: white; font-weight: bold; margin: 0; padding: 10px;')
        self.setup()
        self._timer = QTimer()
        self._timer.setInterval(500)
        self._timer.timeout.connect(self._on_timer)
        self._timer.start()
        self._timer_step = 0
        frida.get_device_manager().on('added', self._on_device)
        frida.get_device_manager().on('removed', self._on_device)
        self.devices_thread = DevicesUpdateThread(self)
        self.devices_thread.onAddDevice.connect(self.on_add_deviceitem)
        self._update_thread = FridaUpdateThread(self)
        self._update_thread.on_status_text.connect(self._update_statuslbl)
        self._update_thread.on_finished.connect(self._frida_updated)
        self._update_thread.onError.connect(self._on_download_error)
        self.updated_frida_version = ''
        self.updated_frida_assets_url = {}
        remote_frida = self._git.get_frida_version()
        if remote_frida is None:
            self.updated_frida_version = ''
            self.updated_frida_assets_url.clear()
        else:
            remote_frida = remote_frida[0]
            self.updated_frida_version = remote_frida['tag_name']
            for asset in remote_frida['assets']:
                try:
                    name = asset['name']
                    tag_start = name.index('android-')
                    if name.index('server') >= 0:
                        tag = name[tag_start + 8:-3]
                        self.updated_frida_assets_url[tag] = asset['browser_download_url']
                except ValueError:
                    pass

    def setup(self):
        """ Setup ui
        """
        h_box = QHBoxLayout()
        h_box.setContentsMargins(0, 0, 0, 0)
        self.update_label = QLabel('Waiting for Device')
        self.update_label.setFixedWidth(self.parent.width())
        self.update_label.setOpenExternalLinks(True)
        self.update_label.setTextFormat(Qt.RichText)
        self.update_label.setFixedHeight(35)
        self.update_label.setTextInteractionFlags(Qt.TextBrowserInteraction)
        self._install_btn = QPushButton('Install Frida', self.update_label)
        self._install_btn.setStyleSheet('padding: 0; border-color: white;')
        self._install_btn.setGeometry(self.update_label.width() - 110, 5, 100, 25)
        self._install_btn.clicked.connect(self._on_install_btn)
        self._install_btn.setVisible(False)
        self._start_btn = QPushButton('Start Frida', self.update_label)
        self._start_btn.setStyleSheet('padding: 0; border-color: white;')
        self._start_btn.setGeometry(self.update_label.width() - 110, 5, 100, 25)
        self._start_btn.clicked.connect(self._on_start_btn)
        self._start_btn.setVisible(False)
        self._update_btn = QPushButton('Update Frida', self.update_label)
        self._update_btn.setStyleSheet('padding: 0; border-color: white;')
        self._update_btn.setGeometry(self.update_label.width() - 110, 5, 100, 25)
        self._update_btn.clicked.connect(self._on_install_btn)
        self._update_btn.setVisible(False)
        self._restart_btn = QPushButton('Restart Frida', self.update_label)
        self._restart_btn.setStyleSheet('padding: 0; border-color: white;')
        self._restart_btn.setGeometry(self.update_label.width() - 110, 5, 100, 25)
        self._restart_btn.clicked.connect(self._on_restart_btn)
        self._restart_btn.setVisible(False)
        h_box.addWidget(self.update_label)
        self.setLayout(h_box)

    def on_add_deviceitem(self, device_name, device_type):
        """ Adds an Item to the DeviceComboBox
        """
        if device_type == self.wait_for_devtype:
            self._timer_step = -1
            self.is_waiting = False
            self.update_label.setStyleSheet('background-color: yellowgreen;')
            self.update_label.setText('Device found: ' + device_name)
            self._adb._check_requirements()
            if self._adb.available():
                device_frida = self._adb.get_frida_version()
                if device_frida is None:
                    self._install_btn.setVisible(True)
                else:
                    if self.updated_frida_version != device_frida:
                        self._update_btn.setVisible(True)
                        if self._adb.is_frida_running():
                            self.onDeviceUpdated.emit()
                    elif device_frida and not self._adb.is_frida_running():
                        self._start_btn.setVisible(True)
                    elif device_frida and self._adb.is_frida_running():
                        self._restart_btn.setVisible(True)
                        self.onDeviceUpdated.emit()

    def _on_timer(self):
        if self._timer_step == -1:
            self._timer.stop()
            return

        if self._timer_step == 0:
            self.update_label.setText(self.update_label.text() + ' .')
            self._timer_step = 1
        elif self._timer_step == 1:
            self.update_label.setText(self.update_label.text() + '.')
            self._timer_step = 2
        elif self._timer_step == 2:
            self.update_label.setText(self.update_label.text() + '.')
            self._timer_step = 3
        else:
            self.update_label.setText(self.update_label.text()[:-self._timer_step])
            self._timer_step = 0
            if self.is_waiting and self.devices_thread is not None:
                if not self.devices_thread.isRunning():
                    self.devices_thread.start()

    def _on_download_error(self, text):
        self._timer_step = -1
        self.update_label.setStyleSheet('background-color: crimson;')
        self.update_label.setText(text)
        self._install_btn.setVisible(True)
        self._update_btn.setVisible(False)

    def _on_device(self):
        self._timer_step = 4
        self.is_waiting = True
        self._on_timer()

    def _on_install_btn(self):
        # urls are empty
        if not self.updated_frida_assets_url:
            return

        arch = self._adb.get_device_arch()
        request_url = ''

        if arch is not None and len(arch) > 1:
            arch = arch.join(arch.split())

            if arch == 'arm64' or arch == 'arm64-v8a':
                request_url = self.updated_frida_assets_url['arm64']
            elif arch == 'armeabi-v7a':
                request_url = self.updated_frida_assets_url['arm']
            else:
                if arch in self.updated_frida_assets_url:
                    request_url = self.updated_frida_assets_url[arch]

            try:
                if self._adb.available() and request_url.index('https://') == 0:
                    self._install_btn.setVisible(False)
                    self._update_btn.setVisible(False)

                    if self._update_thread is not None:
                        if not self._update_thread.isRunning():
                            self._update_thread.frida_url = request_url
                            self._update_thread.adb = self._adb
                            self._update_thread.start()

            except ValueError:
                # something wrong in .git_cache folder
                print("request_url not set")

    def _update_statuslbl(self, text):
        self._timer.stop()
        self._timer_step = 0
        self._timer.start()
        self.update_label.setText(text)

    def _frida_updated(self):
        self._timer_step = 3
        self.is_waiting = True
        self._on_timer()

    def _on_start_btn(self):
        if self._adb.available():
            self._start_btn.setVisible(False)
            if self._adb.start_frida():
                self.onDeviceUpdated.emit()
            else:
                self._start_btn.setVisible(True)

    def _on_restart_btn(self):
        if self._adb.available():
            self._restart_btn.setVisible(False)
            if self._adb.start_frida(restart=True):
                self._restart_btn.setVisible(True)
                self.onDeviceUpdated.emit()


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

    def _update_device(self):
        try:
            self.device = frida.get_usb_device()
            self.proc_list.device = self.device
            self.spawn_list.device = self.device
        except frida.TimedOutError:
            self.device = None

    def setup_ui(self):
        self.setFixedSize(800, 400)
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

        self._dev_bar = DeviceBar(self, self.device_type)
        self._dev_bar.onDeviceUpdated.connect(self._update_device)
        # not needed on local
        if self.device and self.device.type == 'local':
            self._dev_bar.setVisible(False)
        vbox = QVBoxLayout()
        vbox.setContentsMargins(0, 0, 0, 0)
        vbox.addWidget(self._dev_bar)
        vbox.addLayout(inner_hbox)
        self.setLayout(vbox)

    def _pid_selected(self, pid):
        if pid:
            self.onSelectedProcess.emit([self.device, pid])
            self.accept()

    def _spawn_selected(self, spawn):
        if spawn[1]:
            self.onSpwanSelected.emit([self.device, spawn[1]])
            self.accept()
