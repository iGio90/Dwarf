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
import subprocess

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from PyQt5.QtWidgets import *

from lib import utils
from threading import Thread

from ui.dialog_js_editor import JsEditorDialog
from ui.list_pick import PickList
from ui.widget_android_package import AndroidPackageWidget
from ui.widget_item_not_editable import NotEditableListWidgetItem


class WelcomeUi(QSplitter):
    def __init__(self, app, *__args):
        super().__init__(*__args)

        self.app = app

        self.startup_script = ''

        self.setHandleWidth(1)

        box_container = QWidget()
        left_box = QVBoxLayout()
        header = QHBoxLayout()

        icon = QLabel()
        icon.setPixmap(utils.get_app_icon())
        icon.setFixedWidth(75)
        title = QLabel('DWARF')
        title.setFont(QFont('impact', 75, QFont.Normal))

        header.addWidget(icon)
        header.addWidget(title)

        self.commit_list = QListWidget()

        frida_update_box = QHBoxLayout()
        self.frida_update_label = QLabel('device frida version: -\nupdated frida version: -')

        self.frida_update_button = QPushButton('update frida')
        self.frida_update_button.setVisible(False)
        self.frida_update_button.clicked.connect(self.update_frida)

        self.dwarf_update_button = QPushButton('update dwarf')
        self.dwarf_update_button.setVisible(False)
        self.dwarf_update_button.clicked.connect(self.update_dwarf)

        frida_update_box.addWidget(self.frida_update_label)
        frida_update_box.addWidget(self.frida_update_button)
        frida_update_box.addWidget(self.dwarf_update_button)

        left_box.addLayout(header)
        left_box.addWidget(self.commit_list)
        left_box.addLayout(frida_update_box)

        box_container.setLayout(left_box)

        right_box_container = QWidget()
        right_box = QVBoxLayout()

        self.devices_list = QComboBox(self)
        self.devices_list.currentIndexChanged.connect(self.device_picked)
        right_box.addWidget(self.devices_list)

        cols = QHBoxLayout()

        spawns_container = QVBoxLayout()
        spawns_label = QLabel('SPAWN')
        spawns_label.setFont(QFont('impact', 35, QFont.Normal))

        self.spawn_list = PickList(self.on_spawn_picked)
        spawns_container.addWidget(spawns_label)
        spawns_container.addWidget(self.spawn_list)

        procs_container = QVBoxLayout()
        procs_label = QLabel('PROCS')
        procs_label.setFont(QFont('impact', 35, QFont.Normal))

        self.proc_list = PickList(self.on_proc_picked)
        procs_container.addWidget(self.proc_list)
        procs_container.addWidget(procs_label)

        cols.addLayout(spawns_container)
        cols.addLayout(procs_container)
        right_box.addLayout(cols)

        right_box_container.setLayout(right_box)

        self.addWidget(box_container)
        self.addWidget(right_box_container)

        frida.get_device_manager().on('added', self.on_device_changed)
        frida.get_device_manager().on('removed', self.on_device_changed)

        self.setStretchFactor(0, 4)
        self.setStretchFactor(1, 2)

        self.updated_frida_version = ''
        self.updated_frida_assets_url = {}

        Thread(target=self.update_ui_sync).start()

    def on_device_changed(self):
        if self.isVisible():
            self.update_device_ui()
        else:
            self.spawn_list.clear()
            self.proc_list.clear()

    def update_ui_sync(self):
        self.update_device_ui()
        self.update_commits()
        self.update_frida_version()

    def update_commits(self):
        data = self.app.get_dwarf().get_git().get_dwarf_commits()
        if data is None:
            q = NotEditableListWidgetItem('Failed to fetch commit list. Try later.')
            q.setFlags(Qt.NoItemFlags)
            self.commit_list.addItem(q)
            return

        most_recent_remote_commit = ''
        most_recent_local_commit = utils.do_shell_command('git log -1 master --pretty=format:%H')
        most_recent_date = ''
        for commit in data:
            if most_recent_remote_commit == '':
                most_recent_remote_commit = commit['sha']
                if most_recent_remote_commit != most_recent_local_commit:
                    self.dwarf_update_button.setVisible(True)

                    q = NotEditableListWidgetItem('')
                    q.setFlags(Qt.NoItemFlags)
                    self.commit_list.addItem(q)
            commit = commit['commit']
            date = commit['committer']['date'].split('T')
            if most_recent_date != date[0]:
                if most_recent_date != '':
                    q = NotEditableListWidgetItem('')
                    q.setFlags(Qt.NoItemFlags)
                    self.commit_list.addItem(q)
                q = NotEditableListWidgetItem(date[0])
                q.setFlags(Qt.NoItemFlags)
                self.commit_list.addItem(q)
                most_recent_date = date[0]

            q = NotEditableListWidgetItem('%s - %s (%s)' % (date[1][:-1], commit['message'],
                                                            commit['author']['name']))
            q.setFlags(Qt.NoItemFlags)
            q.setForeground(Qt.white)
            self.commit_list.addItem(q)

    def update_dwarf(self, item):
        self.commit_list.clear()
        q = NotEditableListWidgetItem('Updating dwarf...')
        q.setFlags(Qt.NoItemFlags)
        self.commit_list.addItem(q)

        utils.do_shell_command('git fetch -q https://github.com/iGio90/Dwarf.git', stdout=subprocess.DEVNULL)
        utils.do_shell_command('git checkout -f -q master', stdout=subprocess.DEVNULL)
        utils.do_shell_command('git reset --hard FETCH_HEAD', stdout=subprocess.DEVNULL)
        sha = utils.do_shell_command('git log -1 master --pretty=format:%H')

        print('')
        print('')
        print('Dwarf updated to commit := ' + sha)
        print('')
        print('')

        sys.exit(0)

    def update_device_ui(self):
        devices = frida.enumerate_devices()
        self.devices_list.clear()
        should_clear = True
        for device in devices:
            self.devices_list.addItem('%s (%s)' % (device.name, device.type))
            self.devices_list.setItemData(self.devices_list.count() - 1, device.id)
            if device.type == 'usb' and should_clear:
                # set the first usb device found
                should_clear = False
                self.devices_list.setCurrentIndex(self.devices_list.count() - 1)
        if should_clear:
            self.spawn_list.clear()
            self.proc_list.clear()

    def device_picked(self, index):
        id = self.devices_list.itemData(index)
        try:
            device = frida.get_device(id)
        except:
            self.update_device_ui()
            return
        self.app.get_dwarf().device_picked(device)
        self.update_spawn_list(device)
        self.update_proc_list(device)

    def update_spawn_list(self, device):
        self.spawn_list.clear()
        try:
            apps = device.enumerate_applications()
        except:
            return
        last_letter = ''
        for app in sorted(apps, key=lambda x: x.name):
            app_name = app.name
            l = app.name[0].upper()
            if last_letter != l:
                if last_letter != '':
                    q = NotEditableListWidgetItem('')
                    q.setFlags(Qt.NoItemFlags)
                    self.spawn_list.addItem(q)
                last_letter = l
                q = NotEditableListWidgetItem(last_letter)
                q.setFlags(Qt.NoItemFlags)
                self.spawn_list.addItem(q)
            q = AndroidPackageWidget(app_name, app.identifier, 0)
            self.spawn_list.addItem(q)

    def update_proc_list(self, device):
        self.proc_list.clear()
        try:
            procs = device.enumerate_processes()
        except:
            return
        for proc in procs:
            q = AndroidPackageWidget('%s\t%s' % (proc.pid, proc.name), '', proc.pid)
            self.proc_list.addItem(q)

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
                except:
                    pass

        local_version = self.app.get_adb().get_frida_version()
        if local_version:
            local_version = self.app.get_adb().get_frida_version().replace('\n', '')\
                .replace('\n', '').replace('\t', '').replace(' ', '').replace('\r', '')
            try:
                if local_version.index('frida') >= 0:
                    local_version = '-'
            except:
                pass
        else:
            # adb not found or device not found through adb
            self.frida_update_label.setText('device frida version: %s\nupdated frida version: %s'
                                            % ('-', self.updated_frida_version))
            return

        self.frida_update_label.setText('device frida version: %s\nupdated frida version: %s'
                                        % (local_version, self.updated_frida_version))

        self.frida_update_button.setVisible(self.updated_frida_version != local_version)

    def update_frida(self):
        def _update():
            if os.path.exists('frida'):
                os.remove('frida')

            r = None
            arch = self.app.get_adb().get_device_arch().replace('\n', '').replace('\t', '')\
                .replace(' ', '').replace('\r', '')
            if arch == 'arm64' or arch == 'arm64-v8a':
                r = requests.get(self.updated_frida_assets_url['arm64'], stream=True)
            elif arch == 'armeabi-v7a':
                r = requests.get(self.updated_frida_assets_url['arm'], stream=True)
            else:
                if arch in self.updated_frida_assets_url:
                    r = requests.get(self.updated_frida_assets_url[arch], stream=True)
            if r is not None:
                with open('frida.xz', 'wb') as f:
                    for chunk in r.iter_content(chunk_size=1024):
                        if chunk:
                            f.write(chunk)
                res = utils.do_shell_command('unxz frida.xz')
                if len(res) == 0:
                    res = self.app.get_adb().mount_system()
                    if res is None or len(res) == 0:
                        self.app.get_adb().push('frida', '/sdcard/')
                        self.app.get_adb().su('killall -9 frida', stdout=subprocess.DEVNULL)
                        self.app.get_adb().su('mv /sdcard/frida /system/xbin/frida', stdout=subprocess.DEVNULL)
                        self.app.get_adb().su('chmod 755 /system/xbin/frida', stdout=subprocess.DEVNULL)
                        self.update_frida_version()
                        self.app.get_adb().su('frida -D', stdout=subprocess.DEVNULL)
                    os.remove('frida')
                else:
                    os.remove('frida.xz')
            self.update_frida_version()

        self.frida_update_button.setVisible(False)
        self.frida_update_label.setText('downloading latest frida server... please wait...')
        Thread(target=_update).start()

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
