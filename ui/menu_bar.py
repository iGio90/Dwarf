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
import json
import subprocess
from pprint import pprint

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QAction, QFileDialog, QMessageBox, QMenu

from ui.dialog_input import InputDialog
from ui.dialog_list import ListDialog
from ui.dialog_table import TableDialog
from ui.widget_android_package import AndroidPackageWidget
from ui.widget_item_not_editable import NotEditableTableWidgetItem


class MenuBar(object):
    def __init__(self, app_window):
        self.git_available = False

        self.app_window = app_window
        self.menu = app_window.menuBar()

        self.build_dwarf_menu()
        self.build_device_menu()
        self.build_target_menu()
        self.build_hooks_menu()
        self.build_find_menu()
        self.build_session_menu()

    def build_dwarf_menu(self):
        # check git availability
        result = subprocess.run(['git', '--version'], stdout=subprocess.PIPE).stdout.decode('utf8')
        try:
            if result.index('git version') >= 0:
                self.git_available = True
        except:
            pass

        update_action = QAction("&Update dwarf", self.app_window)
        update_action.triggered.connect(self.handler_update)
        update_action.setEnabled(self.git_available)

        dwarf_menu = self.menu.addMenu('&Dwarf')
        dwarf_menu.addAction(update_action)

    def build_device_menu(self):
        packages_action = QAction("&Save APK", self.app_window)
        packages_action.triggered.connect(self.handler_packages)

        device_menu = self.menu.addMenu('&Device')
        device_menu.addAction(packages_action)

    def build_target_menu(self):
        resume_action = QAction("&Resume", self.app_window)
        resume_action.setShortcut("Ctrl+T")
        resume_action.setStatusTip('Resume application')
        resume_action.triggered.connect(self.handler_resume)

        restart_action = QAction("&Restart", self.app_window)
        restart_action.setShortcut("Ctrl+R")
        restart_action.setStatusTip('Restart application')
        restart_action.triggered.connect(self.handler_restart)

        target_menu = self.menu.addMenu('&Target')
        target_menu.addAction(resume_action)
        target_menu.addAction(restart_action)

    def build_hooks_menu(self):
        hook_native_action = QAction("&Native", self.app_window)
        hook_native_action.setShortcut("Ctrl+N")
        hook_native_action.setStatusTip('Hook arbitrary instruction')
        hook_native_action.triggered.connect(self.app_window.get_app_instance().get_hooks_panel().hook_native)

        hook_java_action = QAction("&Java", self.app_window)
        hook_java_action.setShortcut("Ctrl+J")
        hook_java_action.triggered.connect(self.app_window.get_app_instance().get_hooks_panel().hook_java)

        hook_onload_action = QAction("&Module load", self.app_window)
        hook_onload_action.setShortcut("Ctrl+M")
        hook_onload_action.triggered.connect(self.app_window.get_app_instance().get_hooks_panel().hook_onload)

        hooks_menu = self.menu.addMenu('&Hooks')
        hooks_menu.addAction(hook_native_action)
        hooks_menu.addAction(hook_java_action)
        hooks_menu.addAction(hook_onload_action)

    def build_find_menu(self):
        symbol_action = QAction("&Symbol", self.app_window)
        symbol_action.triggered.connect(self.handler_find_symbol)

        find_menu = self.menu.addMenu('&Find')
        find_menu.addAction(symbol_action)

    def build_session_menu(self):
        session_load_action = QAction("&Load", self.app_window)
        session_load_action.setShortcut("Ctrl+O")
        session_load_action.setStatusTip('Load a session from file')
        session_load_action.triggered.connect(self.handler_session_load)

        session_save_action = QAction("&Save", self.app_window)
        session_save_action.setShortcut("Ctrl+S")
        session_save_action.setStatusTip('Load a session from file')
        session_save_action.triggered.connect(self.handler_session_save)

        session_menu = self.menu.addMenu('&Session')
        session_menu.addAction(session_load_action)
        session_menu.addAction(session_save_action)

    def handler_find_symbol(self):
        input = InputDialog().input('find symbol by pattern (*_open*)')
        if input[0]:
            matches = self.app_window.get_app_instance().dwarf_api('findSymbol', input[1])
            if len(matches) > 0:
                data = []
                for ptr in matches:
                    sym = self.app_window.get_app_instance().dwarf_api('getSymbolByAddress', ptr)
                    if sym['name'] is None or sym['name'] == '':
                        sym['name'] = sym['address']
                    data.append(sym)
                TableDialog().build_and_show(self.build_symbol_table, data)

    def handler_packages(self):
        packages = self.app_window.get_adb().list_packages()
        accept, items = ListDialog.build_and_show(
            self.build_packages_list, packages, double_click_to_accept=True)
        if accept:
            if len(items) > 0:
                path = items[0].get_android_package().path
                r = QFileDialog.getSaveFileName()
                if len(r) > 0 and len(r[0]) > 0:
                    self.app_window.get_adb().pull(path, r[0])

    def handler_restart(self):
        self.app_window.get_app_instance().restart()

    def handler_resume(self):
        self.app_window.get_app_instance().resume()

    def handler_session_load(self):
        r = QFileDialog.getOpenFileName()
        if len(r) > 0 and len(r[0]) > 0:
            with open(r[0], 'r') as f:
                session = json.load(f)
                self.app_window.get_app_instance().get_hooks_panel()
                for hook in session['natives']:
                    self.app_window.get_app_instance().get_hooks_panel().hook_native(hook['input'], hook)
                for hook in session['java']:
                    self.app_window.get_app_instance().get_hooks_panel().hook_java(hook['input'], hook)
                for hook in session['onloads']:
                    self.app_window.get_app_instance().get_hooks_panel().hook_onload(hook)

    def handler_session_save(self):
        r = QFileDialog.getSaveFileName()
        if len(r) > 0 and len(r[0]) > 0:
            hooks = []
            for hook in self.app_window.get_app_instance().get_hooks_panel().get_hooks():
                h = self.app_window.get_app_instance().get_hooks_panel().get_hooks()[hook]
                if h.get_input is None or len(h.get_input) == 0:
                    continue
                hooks.append({
                    'input': h.get_input(),
                    'condition': h.get_condition(),
                    'logic': h.get_logic()
                })
            java_hooks = []
            for hook in self.app_window.get_app_instance().get_hooks_panel().get_java_hooks():
                h = self.app_window.get_app_instance().get_hooks_panel().get_java_hooks()[hook]
                java_hooks.append({
                    'input': h.get_input(),
                    'condition': h.get_condition(),
                    'logic': h.get_logic()
                })
            onload_hooks = []
            for hook in self.app_window.get_app_instance().get_hooks_panel().get_onloads():
                onload_hooks.append(
                    self.app_window.get_app_instance().get_hooks_panel().get_onloads()[hook].get_input())
            session = {
                'natives': hooks,
                'java': java_hooks,
                'onloads': onload_hooks,
            }
            with open(r[0], 'w') as f:
                f.write(json.dumps(session))

    def handler_update(self):
        if self.git_available:
            subprocess.run(['git', 'checkout', 'master'])
            subprocess.run(['git', 'fetch', 'origin', 'master'])
            master_hash = subprocess.run(['git', 'log', '-1', '--pretty=format:\"%H\"'],
                                         stdout=subprocess.PIPE).stdout.decode('utf8')
            upstream_hash = subprocess.run(['git', 'log', '-1', 'FETCH_HEAD', '--pretty=format:\"%H\"'],
                                           stdout=subprocess.PIPE).stdout.decode('utf8')
            if master_hash != upstream_hash:
                msg = QMessageBox()
                msg.setText("Updated to latest commit")
                msg.setInformativeText('Restart dwarf to apply changes')
                msg.setWindowTitle("Dwarf")
                msg.setDetailedText(upstream_hash)
            else:
                msg = QMessageBox()
                msg.setText("Dwarf is already updated to latest commit")
            msg.setStandardButtons(QMessageBox.Ok)
            msg.exec_()

    #
    #
    # Just a separator
    #
    #

    def build_packages_list(self, list, data):
        list.setMinimumWidth(int(self.app_window.get_app_instance().width() / 3))
        for ap in sorted(data, key=lambda x: x.package):
            list.addItem(AndroidPackageWidget(ap))

    def build_symbol_table(self, table, data):
        table.setMinimumWidth(int(self.app_window.get_app_instance().width() / 3))
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(['name', 'address', 'module'])

        for sym in sorted(data, key=lambda x: x['name']):
            row = table.rowCount()
            table.insertRow(row)

            q = NotEditableTableWidgetItem(sym['name'])
            q.setForeground(Qt.gray)
            table.setItem(row, 0, q)

            q = NotEditableTableWidgetItem(sym['address'])
            q.setForeground(Qt.red)
            table.setItem(row, 1, q)

            q = NotEditableTableWidgetItem(sym['moduleName'])
            table.setItem(row, 2, q)
        table.resizeColumnToContents(1)
