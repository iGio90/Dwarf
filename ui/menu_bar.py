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
import webbrowser

from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QAction, QFileDialog, QMenuBar, QMenu

from lib import prefs, utils
from ui.dialog_input import InputDialog
from ui.dialog_list import ListDialog
from ui.dialog_table import TableDialog
from ui.widget_android_package import AndroidPackageWidget, AndroidAppWidget
from ui.widget_item_not_editable import NotEditableTableWidgetItem


class MenuBar(object):
    def __init__(self, app_window):
        self.git_available = False

        self.app_window = app_window
        self.menu = app_window.menuBar()

        self.hooks_menu = None

        # actions
        self.menu_actions = []

        self.build_device_menu()
        self.build_process_menu()
        self.build_hooks_menu()
        self.build_find_menu()
        self.build_session_menu()
        self.build_view_menu()
        self.build_about_menu()

    def add_menu_action(self, menu, action, require_script):
        self.menu_actions.append({
            'action': action,
            'require_script': require_script
        })
        action.setEnabled(not require_script)
        menu.addAction(action)

    def build_device_menu(self):
        save_apk = QAction("&Save APK", self.app_window)
        save_apk.triggered.connect(self.handler_save_apk)

        device_menu = self.menu.addMenu('&Device')
        self.add_menu_action(device_menu, save_apk, False)

    def build_process_menu(self):
        resume = QAction("&Resume", self.app_window)
        resume.setShortcut("Ctrl+T")
        resume.setStatusTip('Resume process')
        resume.triggered.connect(self.handler_resume)

        restart = QAction("&Restart", self.app_window)
        restart.setShortcut("Ctrl+R")
        restart.setStatusTip('Restart process')
        restart.triggered.connect(self.handler_restart)

        detach = QAction("&Detach", self.app_window)
        detach.setStatusTip('Deatch process')
        detach.triggered.connect(self.handler_detach)

        process_menu = self.menu.addMenu('&Process')
        self.add_menu_action(process_menu, resume, True)
        self.add_menu_action(process_menu, restart, True)
        self.add_menu_action(process_menu, detach, True)

    def build_hooks_menu(self):
        self.hooks_menu = self.menu.addMenu('&Hooks')

    def build_find_menu(self):
        symbol = QAction("&Symbol", self.app_window)
        symbol.triggered.connect(self.handler_find_symbol)

        find_menu = self.menu.addMenu('&Find')
        self.add_menu_action(find_menu, symbol, True)

    def build_session_menu(self):
        session_load = QAction("&Load", self.app_window)
        session_load.setShortcut("Ctrl+O")
        session_load.setStatusTip('Load a session from file')
        session_load.triggered.connect(self.handler_session_load)

        session_save = QAction("&Save", self.app_window)
        session_save.setShortcut("Ctrl+P")
        session_save.setStatusTip('Load a session from file')
        session_save.triggered.connect(self.handler_session_save)

        session_menu = self.menu.addMenu('&Session')
        self.add_menu_action(session_menu, session_load, False)
        self.add_menu_action(session_menu, session_save, False)

    def build_view_menu(self):
        data = QAction("&Data", self.app_window)
        data.triggered.connect(self.handler_view_data)

        ranges = QAction("&Ranges", self.app_window)
        ranges.triggered.connect(self.handler_view_ranges)

        modules = QAction("&Modules", self.app_window)
        modules.triggered.connect(self.handler_view_modules)

        backtrace = QAction("&Backtrace", self.app_window)
        backtrace.triggered.connect(self.handler_view_backtrace)

        view_menu = self.menu.addMenu('&UI')
        self.add_menu_action(view_menu, data, True)
        view_menu.addSeparator()
        self.add_menu_action(view_menu, ranges, True)
        self.add_menu_action(view_menu, modules, True)
        self.add_menu_action(view_menu, backtrace, True)

    def build_about_menu(self):
        slack = QAction('&Slack', self.app_window)
        slack.triggered.connect(self.handler_slack)
        author = QAction('&Author', self.app_window)
        author.triggered.connect(self.handler_author)

        about_menu = self.menu.addMenu('&About')
        self.add_menu_action(about_menu, slack, False)
        self.add_menu_action(about_menu, author, False)

    def handler_author(self):
        webbrowser.open_new_tab('http://www.giovanni-rocca.com')

    def handler_detach(self):
        self.app_window.get_dwarf().detach()

    def handler_find_symbol(self):
        accept, input = InputDialog().input('find symbol by pattern', placeholder='*_open*')
        if accept:
            matches = self.app_window.get_app_instance().dwarf_api('findSymbol', input)
            if len(matches) > 0:
                data = []
                for ptr in matches:
                    sym = self.app_window.get_app_instance().dwarf_api('getSymbolByAddress', ptr)
                    if sym['name'] == '' or sym['name'] is None:
                        sym['name'] = sym['address']
                    data.append(sym)
                TableDialog().build_and_show(self.build_symbol_table, data)

    def handler_restart(self):
        self.app_window.get_app_instance().restart()

    def handler_resume(self):
        self.app_window.get_app_instance().resume()

    def handler_save_apk(self):
        packages = self.app_window.get_adb().list_packages()
        accept, items = ListDialog.build_and_show(
            self.build_packages_list, packages, double_click_to_accept=True)
        if accept:
            if len(items) > 0:
                path = items[0].get_package_name().path
                r = QFileDialog.getSaveFileName()
                if len(r) > 0 and len(r[0]) > 0:
                    self.app_window.get_adb().pull(path, r[0])

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
                self.app_window.get_app_instance().get_log_panel().set_js_script_text(session['script'])

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
                    'logic': h.get_logic(),
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
                'script': self.app_window.get_app_instance().get_log_panel().get_js_script_text()
            }
            with open(r[0], 'w') as f:
                f.write(json.dumps(session))

    def handler_slack(self):
        webbrowser.open_new_tab('https://join.slack.com/t/resecret/shared_invite'
                                '/enQtMzc1NTg4MzE3NjA1LTlkNzYxNTIwYTc2ZTYyOWY1MT'
                                'Q1NzBiN2ZhYjQwYmY0ZmRhODQ0NDE3NmRmZjFiMmE1MDYwN'
                                'WJlNDVjZDcwNGE')

    def handler_view_backtrace(self):
        visible = self.app_window.get_app_instance().get_backtrace_panel().isVisible()
        self.app_window.get_dwarf().get_prefs().put(prefs.VIEW_BACKTRACE, not visible)
        self.app_window.get_app_instance().get_backtrace_panel().setVisible(not visible)

    def handler_view_data(self):
        self.app_window.get_app_instance().get_data_panel().showMaximized()

    def handler_view_modules(self):
        visible = self.app_window.get_app_instance().get_modules_panel().isVisible()
        self.app_window.get_dwarf().get_prefs().put(prefs.VIEW_MODULES, not visible)
        self.app_window.get_app_instance().get_modules_panel().setVisible(not visible)

    def handler_view_ranges(self):
        visible = self.app_window.get_app_instance().get_ranges_panel().isVisible()
        self.app_window.get_dwarf().get_prefs().put(prefs.VIEW_RANGES, not visible)
        self.app_window.get_app_instance().get_ranges_panel().setVisible(not visible)

    #
    #
    # Just a separator
    #
    #

    def build_packages_list(self, list, data):
        list.setMinimumWidth(int(self.app_window.get_app_instance().width() / 4))
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

    def on_context_info(self):
        self.hooks_menu.clear()

        hook_native = QAction("&Native", self.app_window)
        hook_native.setShortcut("Ctrl+N")
        hook_native.triggered.connect(self.app_window.get_app_instance().get_hooks_panel().hook_native)
        self.add_menu_action(self.hooks_menu, hook_native, True)

        if self.app_window.get_dwarf().java_available:
            hook_java = QAction("&Java", self.app_window)
            hook_java.setShortcut("Ctrl+J")
            hook_java.triggered.connect(self.app_window.get_app_instance().get_hooks_panel().hook_java)
            self.add_menu_action(self.hooks_menu, hook_java, True)

            hook_onload = QAction("&Module load", self.app_window)
            hook_onload.setShortcut("Ctrl+M")
            hook_onload.triggered.connect(self.app_window.get_app_instance().get_hooks_panel().hook_onload)
            self.add_menu_action(self.hooks_menu, hook_onload, True)

    def on_script_destroyed(self):
        for action in self.menu_actions:
            action['action'].setEnabled(not action['require_script'])

    def on_script_loaded(self):
        for action in self.menu_actions:
            action['action'].setEnabled(True)
