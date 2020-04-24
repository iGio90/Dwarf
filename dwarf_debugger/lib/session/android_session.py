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
import frida
from PyQt5.QtWidgets import QMenu, QAction, QFileDialog

from dwarf_debugger.lib.session.session import Session
from dwarf_debugger.lib.android import AndroidDecompileUtil
from dwarf_debugger.lib.adb import Adb

from dwarf_debugger.ui.widgets.apk_list import ApkListDialog
from dwarf_debugger.lib import utils


class AndroidSession(Session):
    """ All Android Stuff goes here
        if u look for something android related its here then
    """

    def __init__(self, app_window):
        super(AndroidSession, self).__init__(app_window)
        self.adb = Adb()

        if not self.adb.min_required:
            utils.show_message_box(self.adb.get_states_string())

    @property
    def session_type(self):
        """ return session name to show in menus etc
        """
        return 'android'

    @property
    def device_manager_type(self):
        return 'usb'

    @property
    def frida_device(self):
        version = frida.__version__.split('.')
        if len(version) == 3:
            if int(version[0]) >= 12 and int(version[1]) >= 7:
                return frida.get_usb_device(timeout=60)

        return frida.get_usb_device()

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

        super()._setup_menu()

        java_menu = QMenu('&Java')
        java_menu.addAction('Trace', self._on_java_trace)
        java_menu.addSeparator()
        java_menu.addAction('Classes', self._on_java_classes)
        self._menu.append(java_menu)

    def start(self, args):
        super().start(args)
        self.adb.device = self.dwarf.device.id

    def decompile_apk(self):
        apk_dlg = ApkListDialog(self._app_window)
        apk_dlg.onApkSelected.connect(self._decompile_package)
        apk_dlg.show()

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
            result = QFileDialog.getSaveFileName(caption='Location to save ' + package,
                                                 directory='./' + package + '.apk', filter='*.apk')
            if result and result[0]:
                self.adb.su_cmd('cp ' + path + ' /sdcard/' + package + '.apk')
                self.adb.pull('/sdcard/' + package + '.apk', result[0])
                self.adb.su_cmd('rm /sdcard/' + package + '.apk')

    def _on_proc_selected(self, data):
        super()._on_proc_selected(data)
        device, pid = data
        if device:
            self.adb.device = device.id

    def _on_spawn_selected(self, data):
        device, package_name, break_at_start = data
        if device:
            self.adb.device = device.id
            self.dwarf.device = device
        if package_name:
            try:
                self.dwarf.spawn(package_name, break_at_start=break_at_start)
            except Exception as e:
                utils.show_message_box('Failed spawning {0}'.format(package_name), str(e))
                self.stop()
                return

            self._on_java_classes()

    def _on_java_trace(self):
        tag = 'jvm-tracer'
        should_request_classes = \
            self._app_window.java_trace_panel is None or tag not in self._app_window.ui_elements
        self._app_window.show_main_tab(tag)
        if should_request_classes:
            self.dwarf.dwarf_api('enumerateJavaClasses')

    def _on_java_classes(self):
        self._app_window.show_main_tab('jvm-inspector')
        self.dwarf.dwarf_api('enumerateJavaClasses')
