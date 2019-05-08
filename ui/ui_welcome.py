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
import sys

import frida
import requests

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor
from PyQt5.QtWidgets import (QHBoxLayout, QVBoxLayout, QSplitter,
    QApplication, QMainWindow, QAction, QWidget, QLabel, QListWidget,
    QAbstractItemView, QPushButton, QComboBox)

from lib import utils

from ui.dialog_js_editor import JsEditorDialog
from ui.list_pick import PickList
from ui.widget_android_package import AndroidPackageWidget
from ui.widget_item_not_editable import NotEditableListWidgetItem

# TODO: renames


class DwarfCommitsThread(QThread):
    """ Commits Thread
    signals:
            on_status_text(str)
            on_add_commit(str, bool) - adds item to list (bool == use white color)
            on_update_available()
            on_finished(str)
    """

    on_status_text = pyqtSignal(str)
    on_update_available = pyqtSignal()
    on_add_commit = pyqtSignal(str, bool)
    on_finished = pyqtSignal(str)

    def __init__(self, parent=None, app=None):
        super().__init__(parent)
        self.app = app

    def run(self):
        self.on_status_text.emit('fetching commit list...')

        try:
            utils.do_shell_command('git --version')
        except IOError as io_error:
            if io_error.errno == 2:
                # git command not available
                self.on_status_text.emit('error: git not available on your system')
                return

        data = self.app.get_dwarf().get_git().get_dwarf_commits()
        if data is None:
            self.on_status_text.emit('Failed to fetch commit list. Try later.')
            return

        most_recent_remote_commit = ''
        most_recent_local_commit = utils.do_shell_command('git log -1 master --pretty=format:%H')
        most_recent_date = ''
        for commit in data:
            if most_recent_remote_commit == '':
                most_recent_remote_commit = commit['sha']
                if most_recent_remote_commit != most_recent_local_commit:
                    self.on_update_available.emit()

            commit = commit['commit']
            date = commit['committer']['date'].split('T')
            if most_recent_date != date[0]:
                if most_recent_date != '':
                    self.on_add_commit.emit('', True)
                self.on_add_commit.emit(date[0], True)
                most_recent_date = date[0]

            s = ('{0} - {1} ({2})'.format(date[1][:-1], commit['message'], commit['author']['name']))
            self.on_add_commit.emit(s, False)

        if most_recent_remote_commit != most_recent_local_commit:
            self.on_finished.emit('There is an newer Version available... You can use the UpdateButton in Menu')
        else:
            # keep: it clears status text
            self.on_finished.emit('')


class DwarfUpdateThread(QThread):
    """ Dwarf update Thread
        signals:
            on_status_text(str)
            on_finished(str)
    """

    on_status_text = pyqtSignal(str)
    on_finished = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

    def run(self):
        self.on_status_text.emit('updating dwarf...')

        try:
            utils.do_shell_command('git --version')
        except IOError as io_error:
            if io_error.errno == 2:
                # git command not available
                self.on_status_text.emit('error while updating: git not available on your system')
                self.on_finished.emit('error while updating: git not available on your system')
                return

        utils.do_shell_command('git fetch -q https://github.com/iGio90/Dwarf.git')
        utils.do_shell_command('git checkout -f -q master')
        utils.do_shell_command('git reset --hard FETCH_HEAD')
        sha = utils.do_shell_command('git log -1 master --pretty=format:%H')

        s = ('Dwarf updated to commit := {0} - Please restart...'.format(sha))
        self.on_status_text.emit(s)
        self.on_finished.emit(sha)


class FridaUpdateThread(QThread):
    """ FridaServer Update Thread
        signals:
            on_status_text(str)
            on_finished()
    """
    on_status_text = pyqtSignal(str)
    on_finished = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.frida_url = ''
        self.adb = None

    def run(self):
        """Runs the UpdateThread
        """

        self.on_status_text.emit('downloading latest frida server... please wait...')

        try:
            request = requests.get(self.frida_url, stream=True)
        except requests.ConnectionError:
            self.on_status_text.emit('unable to download latest frida binary')
            return

        if request is not None and request.status_code == 200:
            with open('frida.xz', 'wb') as frida_archive:
                num = 0
                for chunk in request.iter_content(chunk_size=1024):
                    if num == 0:
                        self.on_status_text.emit('downloading latest frida server... please wait.')
                        num += 1
                    if num == 1:
                        self.on_status_text.emit('downloading latest frida server... please wait..')
                        num += 1
                    if num == 2:
                        self.on_status_text.emit('downloading latest frida server... please wait...')
                        num += 0

                    if chunk:
                        frida_archive.write(chunk)

            self.on_status_text.emit('extracting latest frida server... please wait...')
            # on windows no unxz command
            # todo: use lzma on all systems
            if os.name == 'nt':
                import lzma
                with lzma.open('frida.xz') as frida_archive:
                    with open('frida', 'wb') as frida_binary:
                        frida_binary.write(frida_archive.read())
                        res = ''
                os.remove('frida.xz')
            else:
                res = utils.do_shell_command('unxz frida.xz')

            if not res:
                self.on_status_text.emit('mounting devices filesystem... please wait...')
                # mount system rw
                res = self.adb.mount_system()
                if res is None or not res:
                    self.on_status_text.emit('pushing to device... please wait...')
                    # push file to device
                    self.adb.push('frida', '/sdcard/')
                    self.on_status_text.emit('setting up and starting frida server... please wait...')
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
                        self.on_status_text('failed to start frida')

                os.remove('frida')
            else:
                os.remove('frida.xz')
        else:
            self.on_status_text.emit('failed to download latest frida server')

        self.on_finished.emit()
        self.frida_url = ''


class DevicesUpdateThread(QThread):
    """ Updates DeviceSelector
        signals:
            clear_devices()
            clear_procs()
            clear_spawns()
            add_device(devicename, customdata, currentitem)
            devices_updated()
    """
    clear_devices = pyqtSignal()
    clear_procs = pyqtSignal()
    clear_spawns = pyqtSignal()
    add_device = pyqtSignal(str, str, bool)
    devices_updated = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)

    def run(self):
        # clear lists
        self.clear_devices.emit()
        self.clear_procs.emit()
        self.clear_spawns.emit()

        # get frida devices
        devices = frida.enumerate_devices()

        for device in devices:
            device_string = ('Device: {0} - ({1})'.format(device.name, device.type))
            self.add_device.emit(device_string, device.id, device.type == 'usb')

        self.devices_updated.emit()


class ProcsThread(QThread):
    """ Updates Processlist
        signals:
            clear_proc()
            add_proc(NotEditableListWidgetItem)
            is_error(str) - shows str in statusbar
        device must set before run
    """
    clear_procs = pyqtSignal()
    add_proc = pyqtSignal(NotEditableListWidgetItem)
    is_error = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.device = None

    def run(self):
        self.clear_procs.emit()

        if self.device is not None:
            try:
                procs = self.device.enumerate_processes()

                for proc in procs:
                    proc_item = AndroidPackageWidget('%s\t%s' % (proc.pid, proc.name), '', proc.pid)
                    self.add_proc.emit(proc_item)
            # ServerNotRunningError('unable to connect to remote frida-server: closed')
            except frida.ServerNotRunningError:
                self.is_error.emit('unable to connect to remote frida server: not started')
            except frida.TransportError:
                self.is_error.emit('unable to connect to remote frida server: closed')
            except frida.TimedOutError:
                self.is_error.emit('unable to connect to remote frida server: timedout')
            except Exception:
                self.is_error.emit('something was wrong...')

        self.device = None


class SpawnsThread(QThread):
    """ Updates the SpawnsList
        signals:
            clear_proc()
            add_spawn(NotEditableListWidgetItem)
            is_error(str) - shows str in statusbar
        device must set before run
    """

    clear_spawns = pyqtSignal()
    add_spawn = pyqtSignal(NotEditableListWidgetItem)
    is_error = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.device = None

    def run(self):

        self.clear_spawns.emit()

        if self.device is not None:
            try:
                apps = self.device.enumerate_applications()

                last_letter = ''

                for app in sorted(apps, key=lambda x: x.name):
                    app_name = app.name
                    letter = app.name[0].upper()

                    if last_letter != letter:
                        if last_letter != '':
                            item = NotEditableListWidgetItem('')
                            item.setFlags(Qt.NoItemFlags)
                            self.add_spawn.emit(item)

                        last_letter = letter
                        item = NotEditableListWidgetItem(last_letter)
                        item.setFlags(Qt.NoItemFlags)
                        self.add_spawn.emit(item)

                    item = AndroidPackageWidget(app_name, app.identifier, 0)
                    self.add_spawn.emit(item)
            except frida.ServerNotRunningError:
                self.is_error.emit('unable to connect to remote frida server: not started')
            except frida.TransportError:
                self.is_error.emit('unable to connect to remote frida server: closed')
            except frida.TimedOutError:
                self.is_error.emit('unable to connect to remote frida server: timedout')
            except Exception:
                self.is_error.emit('something was wrong...')

        self.device = None


class WelcomeUi(QSplitter):
    def __init__(self, app, *__args):
        super().__init__(*__args)

        self.app = app

        self.startup_script = ''

        self.menu_bar = None
        self.status_bar = None

        _app = QApplication.instance()
        for w in _app.topLevelWidgets():
            if isinstance(w, QMainWindow):
                #self.menu_bar = w.get_menu()
                self.status_bar = w.get_statusbar()

        self.update_action = QAction('Update Dwarf')
        self.update_action.triggered.connect(self.update_dwarf)

        self.setup_ui()

        self.updated_frida_version = ''
        self.updated_frida_assets_url = {}

        self.frida_update_thread = None
        self.devices_thread = None
        self.procs_update_thread = None
        self.spawns_update_thread = None
        self.update_commits_thread = None
        self.update_dwarf_thread = None

        self.setup_threads()

        frida.get_device_manager().on('added', self.update_device_ui)
        frida.get_device_manager().on('removed', self.update_device_ui)

        if not self.app.get_adb().available():
            # additional check for null local device
            if frida.get_local_device() is None:
                utils.show_message_box('adb/device/emu not found or not rooted! see details or output',
                                       self.app.get_adb().get_states_string())

        self.update_ui_sync()

    def setup_ui(self):
        """ Setups the ui
        """
        left_side = QWidget()
        right_side = QWidget()

        # -------------------------------------------
        # Left Side
        # -------------------------------------------
        wrapper = QVBoxLayout()
        head = QHBoxLayout()

        # dwarf icon
        icon = QLabel()
        icon.setPixmap(self.app.get_icon())
        icon.setFixedWidth(75)
        head.addWidget(icon)

        # main titleDwarf
        title = QLabel('Dwarf')
        title.setFont(QFont('Anton', 58, QFont.Bold))
        head.addWidget(title)

        wrapper.addLayout(head)

        # commit list
        self.commit_list = QListWidget()
        self.commit_list.setSelectionMode(QAbstractItemView.NoSelection)
        wrapper.addWidget(self.commit_list)

        frida_update_box = QHBoxLayout()

        # frida versions
        self.frida_update_label = QLabel('device frida version: -\nupdated frida version: -')
        frida_update_box.addWidget(self.frida_update_label)

        # frida update-button
        self.frida_update_button = QPushButton('update frida')
        self.frida_update_button.setVisible(False)
        self.frida_update_button.clicked.connect(self.update_frida_server)
        frida_update_box.addWidget(self.frida_update_button)

        # frida control-button
        self.frida_control_button = QPushButton('update frida')
        self.frida_control_button.setVisible(False)
        self.frida_control_button.clicked.connect(self.control_frida)
        frida_update_box.addWidget(self.frida_control_button)

        wrapper.addLayout(frida_update_box)

        # finish
        left_side.setLayout(wrapper)

        # -------------------------------------------
        # right side
        # -------------------------------------------
        wrapper = QVBoxLayout()

        # devices label
        devices_label = QLabel('DEVICES')
        devices_label.setFont(QFont('Anton', 20, QFont.Normal))
        wrapper.addWidget(devices_label)

        # devices combobox
        self.devices_list = QComboBox(self)
        self.devices_list.currentIndexChanged.connect(self.device_picked)
        wrapper.addWidget(self.devices_list)

        # procs/spawns lists
        spawns_vbox = QVBoxLayout()

        spawns_label = QLabel('SPAWN')
        spawns_label.setFont(QFont('Anton', 20, QFont.Normal))
        spawns_vbox.addWidget(spawns_label)

        self.spawn_list = PickList(self.on_spawn_picked)
        spawns_vbox.addWidget(self.spawn_list)

        spawns_refresh_button = QPushButton('refresh')
        spawns_refresh_button.clicked.connect(self.on_refresh_spawns)
        spawns_vbox.addWidget(spawns_refresh_button)

        procs_vbox = QVBoxLayout()

        procs_label = QLabel('PROCS')
        procs_label.setFont(QFont('Anton', 20, QFont.Normal))
        procs_vbox.addWidget(procs_label)

        self.proc_list = PickList(self.on_proc_picked)
        procs_vbox.addWidget(self.proc_list)

        procs_refresh_button = QPushButton('refresh')
        procs_refresh_button.clicked.connect(self.on_refresh_procs)
        procs_vbox.addWidget(procs_refresh_button)

        inner_hbox = QHBoxLayout()
        inner_hbox.addLayout(spawns_vbox)
        inner_hbox.addLayout(procs_vbox)
        wrapper.addLayout(inner_hbox)

        # finish
        right_side.setLayout(wrapper)

        # final
        self.addWidget(left_side)
        self.addWidget(right_side)

        self.setAutoFillBackground(True)
        self.setHandleWidth(1)
        self.setStretchFactor(0, 4)
        self.setStretchFactor(1, 2)

    def setup_threads(self):
        """ Setups the Threads used here
        """
        if self.devices_thread is None:
            self.devices_thread = DevicesUpdateThread(self.app)
            self.devices_thread.add_device.connect(self.on_add_deviceitem)
            self.devices_thread.clear_devices.connect(self.on_clear_devicelist)
            self.devices_thread.clear_procs.connect(self.on_clear_proclist)
            self.devices_thread.clear_spawns.connect(self.on_clear_spawnlist)
            self.devices_thread.devices_updated.connect(self.on_devices_updated)

        if self.spawns_update_thread is None:
            self.spawns_update_thread = SpawnsThread(self.app)
            self.spawns_update_thread.add_spawn.connect(self.on_add_spawn)
            self.spawns_update_thread.clear_spawns.connect(self.on_clear_spawnlist)
            self.spawns_update_thread.is_error.connect(self.on_status_text)

        if self.procs_update_thread is None:
            self.procs_update_thread = ProcsThread(self.app)
            self.procs_update_thread.add_proc.connect(self.on_add_proc)
            self.procs_update_thread.clear_procs.connect(self.on_clear_proclist)
            self.procs_update_thread.is_error.connect(self.on_status_text)

        if self.frida_update_thread is None:
            self.frida_update_thread = FridaUpdateThread(self.app)
            self.frida_update_thread.adb = self.app.get_adb()
            self.frida_update_thread.on_status_text.connect(self.frida_status_label)
            self.frida_update_thread.on_finished.connect(self.update_frida_version)
            self.frida_update_thread.adb = self.app.get_adb()

    def update_ui_sync(self):
        self.update_commits()
        self.update_frida_version()
        self.update_device_ui()

    def update_commits(self):
        if self.update_commits_thread is None:
            self.update_commits_thread = DwarfCommitsThread(app=self.app)
            self.update_commits_thread.on_update_available.connect(self.on_dwarf_isupdate)
            self.update_commits_thread.on_add_commit.connect(self.on_dwarf_commit)
            self.update_commits_thread.on_status_text.connect(self.on_status_text)
            self.update_commits_thread.on_finished.connect(self.on_status_text)
            if not self.update_commits_thread.isRunning():
                self.update_commits_thread.start()

    def update_dwarf(self):
        if self.update_dwarf_thread is None:
            self.update_dwarf_thread = DwarfUpdateThread(self.app)
            self.update_dwarf_thread.on_finished.connect(self.on_dwarf_updated)
            self.update_dwarf_thread.on_status_text.connect(self.on_status_text)

            if not self.update_dwarf_thread.isRunning():
                self.update_dwarf_thread.start()

    def on_dwarf_isupdate(self):
        """ Used in DwarfCommitsThread
            enables the UpdateBtn in menu
        """
        # self.menu_bar.menu.addAction(self.update_action)

    def on_dwarf_commit(self, com_text, color=False):
        q = NotEditableListWidgetItem(com_text)
        q.setFlags(Qt.NoItemFlags)
        if color:
            q.setForeground(QColor('#ef5350'))
        self.commit_list.addItem(q)

    def on_status_text(self, text):
        """ Sets text in StatusBar
        """
        if self.status_bar is not None:
            self.status_bar.showMessage(text)

    def on_dwarf_updated(self, sha):
        """ runs after dwarf_update
        """
        if 'error' in sha:
            utils.show_message_box(sha)
            return

        print('')
        print('')
        print('Dwarf updated to commit := ' + sha)
        print('')
        print('')

        utils.show_message_box('Dwarf updated to commit := ' + sha, 'Please restart...')
        sys.exit(0)

    def on_refresh_procs(self):
        self.on_clear_proclist()
        item_id = self.devices_list.itemData(self.devices_list.currentIndex())
        try:
            device = frida.get_device(item_id)
            self.update_proc_list(device)
        except Exception:
            return

    def on_clear_proclist(self):
        """ Clears the ProcList
        """
        self.proc_list.clear()

    def on_refresh_spawns(self):
        self.on_clear_spawnlist()
        item_id = self.devices_list.itemData(self.devices_list.currentIndex())
        try:
            device = frida.get_device(item_id)
            self.update_spawn_list(device)
        except Exception:
            return

    def on_clear_spawnlist(self):
        """ Clears the SpawnList
        """
        self.spawn_list.clear()

    def on_clear_devicelist(self):
        """ Clears Devices ComboBox
        """
        self.devices_list.clear()

    def on_add_deviceitem(self, device_name, custom_data, current=False):
        """ Adds an Item to the DeviceComboBox
        """
        self.devices_list.addItem(device_name, custom_data)
        if current:
            self.devices_list.setCurrentIndex(self.devices_list.count() - 1)

    def on_devices_updated(self):
        self.device_picked(self.devices_list.currentIndex())
        self.devices_list.currentIndexChanged.connect(self.device_picked)

    def update_device_ui(self):
        """ Updates the DeviceComboBox
        """
        if self.devices_thread is not None:
            if not self.devices_thread.isRunning():
                # temp disconnect its reconnected in on_devices_updated
                self.devices_list.currentIndexChanged.disconnect()
                self.devices_thread.start()

    def device_picked(self, index):
        item_id = self.devices_list.itemData(index)
        try:
            device = frida.get_device(item_id)
        except Exception:
            return
        self.app.get_dwarf().device_picked(device)
        self.update_spawn_list(device)
        self.update_proc_list(device)

    def on_add_spawn(self, item):
        self.spawn_list.addItem(item)

    def update_spawn_list(self, device):
        if not device:
            return

        if self.spawns_update_thread is not None:
            if not self.spawns_update_thread.isRunning():
                self.spawns_update_thread.device = device
                self.spawns_update_thread.start()

    def on_add_proc(self, item):
        self.proc_list.addItem(item)

    def update_proc_list(self, device):
        if not device:
            return

        if self.procs_update_thread is not None:
            if not self.procs_update_thread.isRunning():
                self.procs_update_thread.device = device
                self.procs_update_thread.start()

    def control_frida(self):
        """ Controls Frida on Device run/stop
        """
        if self.frida_control_button.text() == 'start frida':
            if self.app.get_adb().available():
                self.app.get_adb().start_frida()
                self.devices_list.currentIndexChanged.disconnect()
                self.on_devices_updated()
        elif self.frida_control_button.text() == 'stop frida':
            if self.app.get_adb().available():
                self.app.get_adb().kill_frida()

        self.update_frida_version()

    def update_frida_version(self):
        data = self.app.get_dwarf().get_git().get_frida_version()
        if data is None:
            self.updated_frida_version = ''
            self.updated_frida_assets_url.clear()
        else:
            data = data[0]
            self.updated_frida_version = data['tag_name']
            for asset in data['assets']:
                try:
                    name = asset['name']
                    tag_start = name.index('android-')
                    if name.index('server') >= 0:
                        tag = name[tag_start + 8:-3]
                        self.updated_frida_assets_url[tag] = asset['browser_download_url']
                except ValueError:
                    pass

        if self.app.get_adb().available():
            local_version = self.app.get_adb().get_frida_version()

            # control button
            if local_version is not None:
                self.frida_control_button.setVisible(True)
                if not self.app.get_adb().is_frida_running():
                    self.frida_control_button.setText('start frida')
                else:
                    self.frida_control_button.setText('stop frida')
            else:
                self.frida_control_button.setVisible(False)

            # update button
            if local_version is not None:
                local_version = local_version.join(local_version.split())
                self.frida_status_label(local_version)
                self.frida_update_button.setVisible(self.updated_frida_version != local_version)
            else:
                self.frida_status_label('frida not found')
                self.frida_update_button.setText('install frida')
                self.frida_update_button.setVisible(True)
                self.frida_update_button.setEnabled(True)
        else:
            self.frida_status_label('-')

    # todo: rename func
    def frida_status_label(self, update_text):
        """ sets status text from fridaserver update
        """
        label_text = ('device frida version: {0}\nupdated frida version: {1}'
                      .format(update_text, self.updated_frida_version))

        self.frida_update_label.setText(label_text)

    def server_update_complete(self):
        """ Fires when FridaServer update is completed
        """
        self.frida_status_label("finished")
        self.update_frida_version()

    def update_frida_server(self):
        """ Updates the FridaServer on the Device
        """

        # urls are empty
        if not self.updated_frida_assets_url:
            return

        arch = self.app.get_adb().get_device_arch()
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
                if self.app.get_adb().available() and request_url.index('https://') == 0:
                    self.frida_update_button.setEnabled(False)

                    if self.frida_update_thread is not None:
                        if not self.frida_update_thread.isRunning():
                            self.frida_update_thread.frida_url = request_url
                            self.frida_update_thread.start()

            except ValueError:
                # something wrong in .git_cache folder
                print("request_url not set")

    def on_proc_picked(self, widget_android_package):
        editor = JsEditorDialog(self.app, def_text=self.startup_script,
                                placeholder_text='// Javascript with frida and dwarf api to run at injection')
        accept, what = editor.show()
        if accept:
            self.startup_script = what
            app_name = widget_android_package.appname
            app_pid = widget_android_package.get_pid()
            if "\t" in app_name:
                app_name = app_name.split("\t")[1]

            self.app.get_dwarf().attach(app_pid, script=what)
            self.app.get_dwarf().app_window.update_title("Dwarf - Attached to %s (pid %s)" % (app_name, app_pid))

    def on_spawn_picked(self, widget_android_package):
        editor = JsEditorDialog(self.app, def_text=self.startup_script,
                                placeholder_text='// Javascript with frida and dwarf api to run at injection')
        accept, what = editor.show()
        if accept:
            self.startup_script = what

            app_name = widget_android_package.appname
            package_name = widget_android_package.get_package_name()

            self.app.get_dwarf().spawn(package_name, script=what)
            self.app.get_dwarf().app_window.update_title("Dwarf - Attached to %s (%s)" % (app_name, package_name))
