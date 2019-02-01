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
import json
import webbrowser

from PyQt5.QtWidgets import QAction, QFileDialog

from lib import prefs
from lib.android import AndroidDecompileUtil
from ui.dialog_input import InputDialog
from ui.dialog_list import ListDialog
from ui.panel_search import SearchPanel
from ui.ui_session import SessionUi
from ui.widget_android_package import AndroidPackageWidget


class MenuBar(object):
    def __init__(self, app_window):
        self.git_available = False

        self.app_window = app_window
        self.menu = app_window.menuBar()

        # actions
        self.menu_actions = []
        self.action_enumerate_java_classes = None
        self.action_find_bytes = None
        self.action_native_trace_start = None
        self.action_native_trace_stop = None

        # menu
        self.kernel_menu = None

        self.build_device_menu()
        self.build_process_menu()
        self.build_kernel_menu()
        self.build_hooks_menu()
        self.build_trace_menu()
        self.build_find_menu()
        self.build_session_menu()
        self.build_view_menu()
        self.build_about_menu()

    def add_menu_action(self, menu, action,
                        require_script=False,
                        require_java=False):
        self.menu_actions.append({
            'action': action,
            'require_script': require_script,
            'require_java': require_java
        })
        if self.app_window.get_dwarf().script is None:
            action.setEnabled(not require_script)
        menu.addAction(action)

    def build_device_menu(self):
        save_apk = QAction("&Save APK", self.app_window)
        save_apk.triggered.connect(self.handler_save_apk)
        decompile_apk = QAction("&Decompile APK", self.app_window)
        decompile_apk.triggered.connect(self.handler_decompile_apk)

        save_apk.setEnabled(self.app_window.get_adb().adb_available)
        decompile_apk.setEnabled(self.app_window.get_adb().adb_available)

        device_menu = self.menu.addMenu('&Device')
        self.add_menu_action(device_menu, save_apk, False)
        self.add_menu_action(device_menu, decompile_apk, False)

    def build_process_menu(self):
        ranges = QAction("&Ranges", self.app_window)
        ranges.triggered.connect(self.handler_view_ranges)

        modules = QAction("&Modules", self.app_window)
        modules.triggered.connect(self.handler_view_modules)

        self.action_enumerate_java_classes = QAction("&Java classes", self.app_window)
        self.action_enumerate_java_classes.triggered.connect(self.handler_enumerate_java_classes)

        dump_memory = QAction("&Dump memory", self.app_window)
        dump_memory.triggered.connect(self.handler_dump_memory)

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
        self.add_menu_action(process_menu, ranges, True)
        self.add_menu_action(process_menu, modules, True)
        self.add_menu_action(process_menu, self.action_enumerate_java_classes, True, True)
        process_menu.addSeparator()
        self.add_menu_action(process_menu, dump_memory, True)
        process_menu.addSeparator()
        self.add_menu_action(process_menu, resume, True)
        self.add_menu_action(process_menu, restart, True)
        self.add_menu_action(process_menu, detach, True)

    def build_kernel_menu(self):
        action_lookup_symbol = QAction("&Lookup Symbol", self.app_window)
        action_lookup_symbol.triggered.connect(self.handler_kernel_lookup_symbol)

        action_ftrace = QAction("&ftrace", self.app_window)
        action_ftrace.triggered.connect(self.handler_kernel_ftrace)

        self.kernel_menu = self.menu.addMenu('&Kernel')
        self.kernel_menu.setEnabled(False)

        self.add_menu_action(self.kernel_menu, action_lookup_symbol, require_script=True)
        self.kernel_menu.addSeparator()
        self.add_menu_action(self.kernel_menu, action_ftrace, require_script=True)

    def build_hooks_menu(self):
        hook_native = QAction("&Native", self.app_window)
        hook_native.setShortcut("Ctrl+N")
        hook_native.triggered.connect(self.app_window.get_dwarf().hook_native)

        hook_java = QAction("&Java", self.app_window)
        hook_java.setShortcut("Ctrl+J")
        hook_java.triggered.connect(self.app_window.get_dwarf().hook_java)

        hook_onload = QAction("&Module load", self.app_window)
        hook_onload.setShortcut("Ctrl+M")
        hook_onload.triggered.connect(self.app_window.get_dwarf().hook_onload)

        hooks_menu = self.menu.addMenu('&Hooks')
        self.add_menu_action(hooks_menu, hook_native, True)
        self.add_menu_action(hooks_menu, hook_java, True, True)
        self.add_menu_action(hooks_menu, hook_onload, True, True)

    def build_trace_menu(self):
        native_menu = self.menu.addMenu('&Native')

        self.action_native_trace_start = QAction("&Start", self.app_window)
        self.action_native_trace_start.triggered.connect(self.handler_trace_native_start)

        self.action_native_trace_stop = QAction("&Stop", self.app_window)
        self.action_native_trace_stop.triggered.connect(self.handler_trace_native_stop)
        self.action_native_trace_stop.setEnabled(False)

        java_tracer = QAction("&Java", self.app_window)
        java_tracer.triggered.connect(self.handler_trace_java)

        native_menu.addAction(self.action_native_trace_start)
        native_menu.addAction(self.action_native_trace_stop)
        trace_menu = self.menu.addMenu('&Trace')
        trace_menu.addMenu(native_menu)
        self.add_menu_action(trace_menu, java_tracer, require_script=True, require_java=True)

    def build_find_menu(self):
        self.action_find_bytes = QAction("&Bytes", self.app_window)
        self.action_find_bytes.triggered.connect(self.handler_find_bytes)

        symbol = QAction("&Symbol", self.app_window)
        symbol.triggered.connect(self.handler_find_symbol)

        find_menu = self.menu.addMenu('&Find')
        self.add_menu_action(find_menu, self.action_find_bytes, True)
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

        hooks = QAction("&Hooks", self.app_window)
        hooks.triggered.connect(self.handler_view_hooks)
        watchers = QAction("&Watchers", self.app_window)
        watchers.triggered.connect(self.handler_view_watchers)
        backtrace = QAction("&Backtrace", self.app_window)
        backtrace.triggered.connect(self.handler_view_backtrace)
        context = QAction("&Context", self.app_window)
        context.triggered.connect(self.handler_view_context)

        view_menu = self.menu.addMenu('&View')
        self.add_menu_action(view_menu, data, True)
        view_menu.addSeparator()
        self.add_menu_action(view_menu, backtrace, True)

    def build_about_menu(self):
        wiki = QAction('&Wiki', self.app_window)
        wiki.triggered.connect(self.handler_wiki)
        slack = QAction('&Slack', self.app_window)
        slack.triggered.connect(self.handler_slack)

        about_menu = self.menu.addMenu('&About')
        self.add_menu_action(about_menu, wiki, False)
        self.add_menu_action(about_menu, slack, False)

    def _set_panel_visibility(self, panel, pref):
        if panel is None:
            return

        visible = panel.isVisible()
        self.app_window.get_dwarf().get_prefs().put(pref, not visible)
        panel.setVisible(not visible)

    def handler_decompile_apk(self):
        packages = self.app_window.get_adb().list_packages()
        if packages:
            accept, items = ListDialog.build_and_show(
                self.build_packages_list, packages, double_click_to_accept=True)
            if accept:
                if len(items) > 0:
                    path = items[0].get_apk_path()
                    AndroidDecompileUtil.decompile(self.app_window.get_adb(), path)

    def handler_detach(self):
        self.app_window.get_dwarf().detach()

    def handler_dump_memory(self):
        self.app_window.get_dwarf().dump_memory()

    def handler_enumerate_java_classes(self, should_update_java_classes=False):
        if not should_update_java_classes:
            should_update_java_classes = self.app_window.get_app_instance().get_java_classes_panel() is None
            self.action_enumerate_java_classes.setEnabled(False)
        self.app_window.get_app_instance().get_session_ui().add_dwarf_tab(
            SessionUi.TAB_JAVA_CLASSES, request_focus=True)
        if should_update_java_classes:
            self.app_window.get_dwarf().dwarf_api('enumerateJavaClasses')

    def handler_find_bytes(self):
        accept, input = InputDialog().input(self.app_window, 'find bytes', placeholder='ff b3 ac 9d 0f ...')
        if accept:
            self.action_find_bytes.setEnabled(False)
            SearchPanel.bytes_search_panel(self.app_window.get_app_instance(), input)

    def handler_find_symbol(self):
        accept, input = InputDialog().input(self.app_window, 'find symbol by pattern', placeholder='*_open*')
        if accept and len(input) > 0:
            SearchPanel.debug_symbol_search_panel(self.app_window.get_app_instance(), input)

    def handler_kernel_lookup_symbol(self):
        accept, input = InputDialog().input(self.app_window, 'lookup kernel symbol by exact name',
                                            placeholder='SyS_open')
        if accept and len(input) > 0:
            self.app_window.get_dwarf().get_kernel().lookup_symbol(input)

    def handler_kernel_ftrace(self):
        self.app_window.get_app_instance().get_session_ui().add_dwarf_tab(SessionUi.TAB_FTRACE, request_focus=True)

    def handler_restart(self):
        self.app_window.get_app_instance().restart()

    def handler_resume(self):
        self.app_window.get_app_instance().resume()

    def handler_save_apk(self):
        packages = self.app_window.get_adb().list_packages()
        if packages:
            accept, items = ListDialog.build_and_show(
                self.build_packages_list, packages, double_click_to_accept=True)
            if accept:
                if len(items) > 0:
                    path = items[0].get_apk_path()
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
                    self.app_window.get_dwarf().hook_native(hook['input'], hook)
                for hook in session['java']:
                    self.app_window.get_dwarf().hook_java(hook['input'], hook)
                for hook in session['onloads']:
                    self.app_window.get_dwarf().hook_onload(hook)
                self.app_window.get_app_instance().get_console_panel().\
                    get_js_console().set_js_script_text(session['script'])

    def handler_session_save(self):
        r = QFileDialog.getSaveFileName()
        if len(r) > 0 and len(r[0]) > 0:
            hooks = []
            for hook in self.app_window.get_dwarf().hooks:
                h = self.app_window.get_dwarf().hooks[hook]
                if h.get_input is None or len(h.get_input) == 0:
                    continue
                hooks.append({
                    'input': h.get_input(),
                    'condition': h.get_condition(),
                    'logic': h.get_logic(),
                })
            java_hooks = []
            for hook in self.app_window.get_dwarf().java_hooks:
                h = self.app_window.get_dwarf().java_hooks[hook]
                java_hooks.append({
                    'input': h.get_input(),
                    'condition': h.get_condition(),
                    'logic': h.get_logic()
                })
            onload_hooks = []
            for hook in self.app_window.get_dwarf().on_loads:
                onload_hooks.append(
                    self.app_window.get_dwarf().on_loads[hook].get_input())
            session = {
                'natives': hooks,
                'java': java_hooks,
                'onloads': onload_hooks,
                'script': self.app_window.get_app_instance().get_console_panel().get_js_console().get_js_script_text()
            }
            with open(r[0], 'w') as f:
                f.write(json.dumps(session))

    def handler_slack(self):
        webbrowser.open_new_tab('https://join.slack.com/t/resecret/shared_invite'
                                '/enQtMzc1NTg4MzE3NjA1LTlkNzYxNTIwYTc2ZTYyOWY1MT'
                                'Q1NzBiN2ZhYjQwYmY0ZmRhODQ0NDE3NmRmZjFiMmE1MDYwN'
                                'WJlNDVjZDcwNGE')

    def handler_trace_java(self):
        should_request_classes = self.app_window.get_app_instance().get_java_trace_panel() is None
        self.app_window.get_app_instance().get_session_ui().add_dwarf_tab(SessionUi.TAB_JAVA_TRACE, request_focus=True)
        if should_request_classes:
            self.app_window.get_dwarf().dwarf_api('enumerateJavaClasses')

    def handler_trace_native_start(self):
        self.app_window.get_dwarf().native_tracer_start()

    def handler_trace_native_stop(self):
        self.app_window.get_dwarf().native_tracer_stop()

    def handler_view_data(self):
        self.app_window.get_app_instance().get_session_ui().add_dwarf_tab(SessionUi.TAB_DATA, request_focus=True)

    def handler_view_backtrace(self):
        self._set_panel_visibility(self.app_window.get_app_instance().get_backtrace_panel(), prefs.VIEW_BACKTRACE)

    def handler_view_context(self):
        self._set_panel_visibility(self.app_window.get_app_instance().get_contexts_panel(), prefs.VIEW_CONTEXT)

    def handler_view_hooks(self):
        self._set_panel_visibility(self.app_window.get_app_instance().get_hooks_panel(), prefs.VIEW_HOOKS)

    def handler_view_modules(self):
        self.app_window.get_app_instance().get_session_ui().add_dwarf_tab(SessionUi.TAB_MODULES, request_focus=True)

    def handler_view_ranges(self):
        self.app_window.get_app_instance().get_session_ui().add_dwarf_tab(SessionUi.TAB_RANGES, request_focus=True)

    def handler_view_watchers(self):
        self._set_panel_visibility(self.app_window.get_app_instance().get_watchers_panel(), prefs.VIEW_WATCHERS)

    def handler_wiki(self):
        webbrowser.open_new_tab('https://github.com/iGio90/Dwarf/wiki')

    #
    #
    # Just a separator
    #
    #

    def build_packages_list(self, list, data):
        list.setMinimumWidth(int(self.app_window.get_app_instance().width() / 4))
        for ap in sorted(data, key=lambda x: x.package):
            list.addItem(AndroidPackageWidget(ap.package, ap.package, 0, apk_path=ap.path))

    def enable_kernel_menu(self):
        self.kernel_menu.setEnabled(True)

    def on_bytes_search_complete(self):
        if self.app_window.get_dwarf().script is not None:
            self.action_find_bytes.setEnabled(True)

    def on_context_info(self):
        for action in self.menu_actions:
            if action['require_java'] and not self.app_window.get_dwarf().java_available:
                action['action'].setEnabled(False)

    def on_java_classes_enumeration_complete(self):
        if self.app_window.get_dwarf().script is not None:
            self.action_enumerate_java_classes.setEnabled(True)

    def on_native_tracer_change(self, started):
        self.action_native_trace_start.setEnabled(not started)
        self.action_native_trace_stop.setEnabled(started)

    def on_script_destroyed(self):
        self.kernel_menu.setEnabled(False)

        for action in self.menu_actions:
            action['action'].setEnabled(not action['require_script'])

    def on_script_loaded(self):

        for action in self.menu_actions:
            if action['require_java'] and not self.app_window.get_dwarf().java_available:
                action['action'].setEnabled(False)
                continue
            action['action'].setEnabled(True)
