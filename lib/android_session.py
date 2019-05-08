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
import json

import frida
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import QMenu, QAction, QFileDialog

from lib.session import Session
from lib.android import AndroidDecompileUtil
from lib.adb import Adb

from ui.dialog_list import ListDialog
from ui.dialog_input import InputDialog

from ui.widget_android_package import AndroidPackageWidget
from ui.widget_item_not_editable import NotEditableListWidgetItem

from ui.device_window import DeviceWindow
from ui.apk_list import ApkListDialog
from lib import utils


class SmaliThread(QThread):
    onFinished = pyqtSignal(name='onFinished')
    onError = pyqtSignal(name='onError')

    def __init__(self, parent=None, package_name=None):
        super(SmaliThread, self).__init__(parent)
        self._adb = Adb()
        self._package_name = package_name
        if not self._adb.available():
            return

    def run(self):
        if not self._adb.available():
            self.onError.emit()
            return

        if not self._package_name:
            self.onError.emit()
            return

        _path = self._adb.package_path(self._package_name)
        if not os.path.exists('.tmp'):
            os.mkdir('.tmp')

        if _path:
            self._adb.pull(_path, '.tmp/base.apk')
            if os.path.exists('.tmp/base.apk'):
                _baksmali_cmd = 'd2j-baksmali.sh'
                if os.name == 'nt':
                    _baksmali_cmd = _baksmali_cmd.replace('.sh', '.bat')
                utils.do_shell_command(_baksmali_cmd + ' .tmp/base.apk -o .tmp/smali')
                self.onFinished.emit()

        self.onError.emit()


class AndroidSession(Session):
    """ All Android Stuff goes here
        if u look for something android related its here then
    """

    def __init__(self, app_window):
        super(AndroidSession, self).__init__(app_window)
        self._app_window = app_window

        self.adb = Adb()

        if not self.adb.is_adb_available():
            utils.show_message_box(self.adb.get_states_string())

        self._device_window = DeviceWindow(self._app_window, 'usb')

        # main menu every session needs
        self._menu = [QMenu(self.session_type + ' Session')]
        #self._menu[0].addAction('Save Session', self._save_session)
        self._menu[0].addAction('Close Session', self.stop_session)

    @property
    def session_ui_sections(self):
        # what sections we want in session_ui
        return ['hooks', 'threads', 'registers', 'memory', 'console', 'watchers']

    @property
    def session_type(self):
        """ return session name to show in menus etc
        """
        return 'Android'

    @property
    def main_menu(self):
        """ return our created menu
        """
        return self._menu

    def initialize(self, config):
        # session supports load/save then use config

        # setup ui etc for android
        self._setup_menu()
        # all fine were done wait for ui_ready
        self.onCreated.emit()

    def _setup_menu(self):
        """ Build Menus
        """
        # additional menus
        file_menu = QMenu('&Device')
        save_apk = QAction("&Save APK", self)
        save_apk.triggered.connect(self.save_apk)
        decompile_apk = QAction("&Decompile APK", self)
        decompile_apk.triggered.connect(self.decompile_apk)

        file_menu.addAction(save_apk)
        file_menu.addAction(decompile_apk)

        self._menu.append(file_menu)

        process_menu = QMenu('&Process')
        process_menu.addAction('Resume', self._on_proc_resume, Qt.Key_F5)
        process_menu.addAction('Restart', self._on_proc_restart, Qt.Key_F9)
        process_menu.addAction('Detach', self._on_detach, Qt.Key_F10)

        self._menu.append(process_menu)

        java_menu = QMenu('&Java')
        java_menu.addAction('Trace', self._on_java_trace)
        java_menu.addSeparator()
        java_menu.addAction('Classes', self._on_java_classes)
        self._menu.append(java_menu)

    def stop_session(self):
        # cleanup ur stuff

        # end session
        super().stop()

    def start(self, args):
        self.dwarf.onScriptDestroyed.connect(self.stop)
        if args.package is None:
            self._device_window.setModal(True)
            self._device_window.onSelectedProcess.connect(self.on_proc_selected)
            self._device_window.onSpwanSelected.connect(self.on_spawn_selected)
            self._device_window.onClosed.connect(self._on_devdlg_closed)
            self._device_window.show()
        else:
            self.dwarf.device = frida.get_usb_device()
            if not args.spawn:
                print('* Trying to attach to {0}'.format(args.package))
                ret_val = self.dwarf.attach(args.package, args.script, False)
                if ret_val == 2:
                    print('Failed to attach: use -sp to force spawn')
                    self.stop()
                    exit()
            else:
                print('* Trying to spawn {0}'.format(args.package))
                ret_val = self.dwarf.spawn(args.package, args.script)
                if ret_val != 0:
                    print('-failed-')
                    exit(ret_val)

    def decompile_apk(self):
        apk_dlg = ApkListDialog(self._app_window)
        apk_dlg.onApkSelected.connect(self._decompile_package)
        apk_dlg.show()
        """
        packages = self.adb.list_packages()
        if packages:
            accept, items = ListDialog.build_and_show(
                self.build_packages_list,
                packages,
                double_click_to_accept=True)
            if accept:
                if len(items) > 0:
                    path = items[0].get_apk_path()
                    AndroidDecompileUtil.decompile(self.adb, path)"""

    def _decompile_package(self, data):
        package, path = data
        if path is not None:
            # todo: make qthread
            AndroidDecompileUtil.decompile(self.adb, path)

    def save_apk(self):
        apk_dlg = ApkListDialog(self._app_window)
        apk_dlg.onApkSelected.connect(self._save_package)
        apk_dlg.show()

    def _save_package(self, data):
        package, path = data
        if path is not None:
            result = QFileDialog.getSaveFileName(caption='Location to save ' + package, directory='./' + package + '.apk', filter='*.apk')
            if result and result[0]:
                self.adb.pull(path, result[0])

    def on_proc_selected(self, data):
        device, pid = data
        if device:
            self.dwarf.device = device
        if pid:
            self.dwarf.attach(pid)

    def on_spawn_selected(self, data):
        device, package_name = data
        if device:
            self.dwarf.device = device
        if package_name:
            if self.dwarf.spawn(package=package_name):
                self.stop()

            # smalistuff
            self._app_window.show_progress('Baksmali ' + package_name + ' ...')
            _smali_thread = SmaliThread(self, package_name)
            _smali_thread.onError.connect(self._app_window.hide_progress)
            _smali_thread.onFinished.connect(self._app_window.hide_progress)
            _smali_thread.start()

            self._on_java_classes()

    def _on_proc_resume(self, tid=0):
        if tid == 0:
            self._app_window.contexts_list_panel.clear()
            self._app_window.context_panel.clear()
            # self._app_window.backtrace_panel.setRowCount(0)
            self._app_window.memory_panel.clear_panel()
            self.dwarf.contexts.clear()

        self.dwarf.dwarf_api('release', tid)

    def _on_proc_restart(self):
        self.dwarf.dwarf_api('restart')
        self._on_proc_resume()

    def _on_detach(self):
        self.dwarf.detach()

    def _on_java_trace(self):
        should_request_classes = self._app_window.java_trace_panel is None
        if self._app_window.java_trace_panel is None:
            self._app_window._create_ui_elem('java-trace')

        self._app_window.show_main_tab('java-trace')
        if should_request_classes:
            self.dwarf.dwarf_api('enumerateJavaClasses')

    def _on_java_classes(self):
        #should_request_classes = self._app_window.java is None
        if self._app_window.java_inspector_panel is None:
            self._app_window._create_ui_elem('java-inspector')

        self._app_window.show_main_tab('java-inspector')
        self.dwarf.dwarf_api('enumerateJavaClasses')

    def _on_devdlg_closed(self):
        if self.dwarf.device is None:
            self.stop_session()
