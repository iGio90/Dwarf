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

from PyQt5.QtWidgets import QAction, QFileDialog, QMessageBox


class MenuBar(object):
    def __init__(self, app_window):
        self.git_available = False

        self.app_window = app_window
        self.menu = app_window.menuBar()

        self.build_dwarf_menu()
        self.build_target_menu()
        self.build_hooks_menu()
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
                onload_hooks.append(self.app_window.get_app_instance().get_hooks_panel().get_onloads()[hook].get_input())
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
            master_hash = subprocess.run(['git', 'log', '-1', '--pretty=format:\"%H\"'], stdout=subprocess.PIPE).stdout.decode('utf8')
            upstream_hash = subprocess.run(['git', 'log', '-1', 'FETCH_HEAD', '--pretty=format:\"%H\"'], stdout=subprocess.PIPE).stdout.decode('utf8')
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

