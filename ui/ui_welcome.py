"""
Dwarf - Copyright (C) 2018 iGio90

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
import sys

import frida
import requests
import subprocess

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QPixmap, QFont
from PyQt5.QtWidgets import QSplitter, QVBoxLayout, QWidget, QHBoxLayout, QLabel, QListWidget

from lib import utils
from threading import Thread

from ui.list_pick import PickList
from ui.widget_android_package import AndroidPackageWidget
from ui.widget_item_not_editable import NotEditableListWidgetItem


class WelcomeUi(QSplitter):
    def __init__(self, app, *__args):
        super().__init__(*__args)

        self.app = app

        box_container = QWidget()
        box = QVBoxLayout()
        header = QHBoxLayout()

        icon = QLabel()
        icon.setPixmap(utils.get_app_icon())
        icon.setFixedWidth(75)
        title = QLabel('DWARF')
        title.setFont(QFont('impact', 75, QFont.Normal))

        header.addWidget(icon)
        header.addWidget(title)

        self.commit_list = QListWidget()

        box.addLayout(header)
        box.addWidget(self.commit_list)

        box_container.setLayout(box)

        left_box_container = QWidget()
        left_box = QHBoxLayout()

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

        left_box.addLayout(spawns_container)
        left_box.addLayout(procs_container)

        left_box_container.setLayout(left_box)

        self.addWidget(box_container)
        self.addWidget(left_box_container)

        frida.get_device_manager().on('added', self.on_device_changed)
        frida.get_device_manager().on('removed', self.on_device_changed)

        self.setStretchFactor(0, 4)
        self.setStretchFactor(1, 2)

        Thread(target=self.update_ui_sync).start()

    def on_device_changed(self):
        if self.isVisible():
            self.update_device_ui()
        else:
            self.spawn_list.clear()
            self.proc_list.clear()

    def update_ui_sync(self):
        self.update_commits()
        self.update_device_ui()

    def update_commits(self):
        r = None
        try:
            r = requests.get('https://api.github.com/repos/iGio90/dwarf/commits')
        except:
            pass
        if r is None or r.status_code != 200:
            q = NotEditableListWidgetItem('Failed to fetch commit list. Try later.')
            q.setFlags(Qt.NoItemFlags)
            self.commit_list.addItem(q)
            return

        most_recent_remote_commit = ''
        most_recent_local_commit = utils.do_shell_command('git log -1 master --pretty=format:%H')
        most_recent_date = ''
        for commit in r.json():
            if most_recent_remote_commit == '':
                most_recent_remote_commit = commit['sha']
                if most_recent_remote_commit != most_recent_local_commit:
                    q = NotEditableListWidgetItem('Update dwarf')
                    q.setForeground(Qt.green)
                    self.commit_list.itemClicked.connect(self.update_dwarf)
                    self.commit_list.addItem(q)

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
        for device in devices:
            if device.type == 'usb':
                self.update_spawn_list(device)
                self.update_proc_list(device)
                return
        self.spawn_list.clear()
        self.proc_list.clear()

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

    def on_proc_picked(self, widget_android_package):
        self.app.get_dwarf().attach(widget_android_package.get_pid())

    def on_spawn_picked(self, widget_android_package):
        self.app.get_dwarf().spawn(widget_android_package.get_package_name())
