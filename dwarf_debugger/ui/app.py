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

import json
import os
import sys

from PyQt5.QtCore import Qt, pyqtSignal, pyqtSlot, QSettings, QUrl
from PyQt5.QtGui import QFont, QFontDatabase, QDesktopServices, QKeySequence
from PyQt5.QtWidgets import (QMainWindow, QApplication, QProgressBar, QTabBar,
                             QStatusBar, QDockWidget, QTabWidget, QMenu, QWidget)

from dwarf_debugger.lib import utils
from dwarf_debugger.lib.prefs import Prefs
from dwarf_debugger.lib.session.session_manager import SessionManager
from dwarf_debugger.lib.plugin_manager import PluginManager

from dwarf_debugger.ui.dialogs.about_dlg import AboutDialog
from dwarf_debugger.ui.dialogs.detached import QDialogDetached
from dwarf_debugger.ui.welcome_window import WelcomeDialog
from dwarf_debugger.ui.widgets.hex_edit import HighLight, HighlightExistsError


class AppWindow(QMainWindow):
    onRestart = pyqtSignal(name='onRestart')
    onSystemUIElementCreated = pyqtSignal(str, QWidget, name='onSystemUIElementCreated')
    onSystemUIElementRemoved = pyqtSignal(str, name='onSystemUIElementRemoved')

    def __init__(self, dwarf_args, flags=None):
        super(AppWindow, self).__init__(flags)

        self.dwarf_args = dwarf_args

        self.session_manager = SessionManager(self)
        self.session_manager.sessionCreated.connect(self.session_created)
        self.session_manager.sessionStopped.connect(self.session_stopped)
        self.session_manager.sessionClosed.connect(self.session_closed)

        self._tab_order = [
            'debug', 'modules', 'ranges', 'jvm-inspector', 'jvm-debugger'
        ]

        self._is_newer_dwarf = False
        self.q_settings = QSettings(utils.home_path() + "dwarf_window_pos.ini", QSettings.IniFormat)

        self.menu = self.menuBar()
        self.view_menu = None

        self._initialize_ui_elements()

        self.setWindowTitle(
            'Dwarf - A debugger for reverse engineers, crackers and security analyst'
        )

        # load external assets
        _app = QApplication.instance()

        # themes
        self.prefs = Prefs()
        utils.set_theme(self.prefs.get('dwarf_ui_theme', 'dark'), self.prefs)

        # load font
        if os.path.exists(utils.resource_path('assets/Anton.ttf')):
            QFontDatabase.addApplicationFont(
                utils.resource_path('assets/Anton.ttf'))
        else:
            QFontDatabase.addApplicationFont(':/assets/Anton.ttf')

        if os.path.exists(utils.resource_path('assets/OpenSans-Regular.ttf')):
            QFontDatabase.addApplicationFont(
                utils.resource_path('assets/OpenSans-Regular.ttf'))
        else:
            QFontDatabase.addApplicationFont(':/assets/OpenSans-Regular.ttf')

        if os.path.exists(utils.resource_path('assets/OpenSans-Bold.ttf')):
            QFontDatabase.addApplicationFont(
                utils.resource_path('assets/OpenSans-Bold.ttf'))
        else:
            QFontDatabase.addApplicationFont(':/assets/OpenSans-Bold.ttf')

        font = QFont("OpenSans", 9, QFont.Normal)
        # TODO: add settingsdlg
        font_size = self.prefs.get('dwarf_ui_font_size', 12)
        font.setPixelSize(font_size)
        _app.setFont(font)

        # mainwindow statusbar
        self.progressbar = QProgressBar()
        self.progressbar.setRange(0, 0)
        self.progressbar.setVisible(False)
        self.progressbar.setFixedHeight(15)
        self.progressbar.setFixedWidth(100)
        self.progressbar.setTextVisible(False)
        self.progressbar.setValue(30)
        self.statusbar = QStatusBar(self)
        self.statusbar.setAutoFillBackground(False)
        self.statusbar.addPermanentWidget(self.progressbar)
        self.statusbar.setObjectName("statusbar")
        self.setStatusBar(self.statusbar)

        self.main_tabs = QTabWidget(self)
        self.main_tabs.setMovable(False)
        self.main_tabs.setTabsClosable(True)
        self.main_tabs.setAutoFillBackground(True)
        self.main_tabs.tabCloseRequested.connect(self._on_close_tab)
        self.setCentralWidget(self.main_tabs)

        # pluginmanager
        self.plugin_manager = PluginManager(self)
        self.plugin_manager.reload_plugins()

        self.welcome_window = None
        if dwarf_args.any == '':
            self.welcome_window = WelcomeDialog(self)
            self.welcome_window.setModal(True)
            self.welcome_window.onIsNewerVersion.connect(
                self._enable_update_menu)
            self.welcome_window.onUpdateComplete.connect(
                self._on_dwarf_updated)
            self.welcome_window.setWindowTitle(
                'Welcome to Dwarf - A debugger for reverse engineers, crackers and security analyst'
            )
            self.welcome_window.onSessionSelected.connect(self._start_session)
            # wait for welcome screen
            self.hide()
            self.welcome_window.show()
        else:
            print('* Starting new Session')
            self._start_session(dwarf_args.target)

    def _initialize_ui_elements(self):
        # dockwidgets
        self.watchpoints_dwidget = None
        self.breakpoint_dwiget = None
        self.bookmarks_dwiget = None
        self.registers_dock = None
        self.console_dock = None
        self.backtrace_dock = None
        self.threads_dock = None
        # panels
        self.asm_panel = None
        self.backtrace_panel = None
        self.bookmarks_panel = None
        self.console_panel = None
        self.context_panel = None
        self.debug_panel = None
        self.contexts_list_panel = None
        self.data_panel = None
        self.ftrace_panel = None
        self.breakpoints_panel = None
        self.objc_inspector_panel = None
        self.java_inspector_panel = None
        self.java_explorer_panel = None
        self.java_trace_panel = None
        self.modules_panel = None
        self.ranges_panel = None
        self.search_panel = None
        self.smali_panel = None
        self.watchpoints_panel = None

        self._ui_elems = []

    def _setup_main_menu(self):
        self.menu = self.menuBar()
        dwarf_menu = QMenu('Dwarf', self)
        theme = QMenu('Theme', dwarf_menu)
        theme.addAction('Black')
        theme.addAction('Dark')
        theme.addAction('Light')
        theme.triggered.connect(self._set_theme)
        dwarf_menu.addMenu(theme)
        dwarf_menu.addSeparator()

        if self._is_newer_dwarf:
            dwarf_menu.addAction('Update', self._update_dwarf)
        dwarf_menu.addAction('Close', self.close)
        self.menu.addMenu(dwarf_menu)

        session = self.session_manager.session
        if session is not None:
            session_menu = session.main_menu
            if isinstance(session_menu, list):
                for menu in session_menu:
                    self.menu.addMenu(menu)
            else:
                self.menu.addMenu(session_menu)

        # plugins
        if self.plugin_manager.plugins:
            self.plugin_menu = QMenu('Plugins', self)
            for plugin in self.plugin_manager.plugins:
                plugin_instance = self.plugin_manager.plugins[plugin]
                plugin_sub_menu = self.plugin_menu.addMenu(plugin_instance.name)

                try:
                    actions = plugin_instance.__get_top_menu_actions__()
                    for action in actions:
                        plugin_sub_menu.addAction(action)
                except:
                    pass

                if not plugin_sub_menu.isEmpty():
                    plugin_sub_menu.addSeparator()

                about = plugin_sub_menu.addAction('About')
                about.triggered.connect(
                    lambda x, item=plugin: self._show_plugin_about(item))

            if not self.plugin_menu.isEmpty():
                self.menu.addMenu(self.plugin_menu)

        self.view_menu = QMenu('View', self)
        self.panels_menu = QMenu('Panels', self.view_menu)
        self.panels_menu.addAction(
            'Search',
            lambda: self.show_main_tab('search'),
            shortcut=QKeySequence(Qt.CTRL + Qt.Key_F3))
        self.panels_menu.addAction(
            'Modules',
            lambda: self.show_main_tab('modules')
        )
        self.panels_menu.addAction(
            'Ranges',
            lambda: self.show_main_tab('ranges')
        )

        self.view_menu.addMenu(self.panels_menu)

        self.debug_view_menu = self.view_menu.addMenu('Debug')

        self.view_menu.addSeparator()

        self.view_menu.addAction('Hide all', self._hide_all_widgets, shortcut=QKeySequence(Qt.CTRL + Qt.Key_F1))
        self.view_menu.addAction('Show all', self._show_all_widgets, shortcut=QKeySequence(Qt.CTRL + Qt.Key_F2))

        self.view_menu.addSeparator()

        self.menu.addMenu(self.view_menu)

        if self.dwarf_args.debug_script:
            debug_menu = QMenu('Debug', self)
            debug_menu.addAction('Reload core', self._menu_reload_core)
            debug_menu.addAction('Debug dwarf js core', self._menu_debug_dwarf_js)
            self.menu.addMenu(debug_menu)

        # tools
        _tools = self.prefs.get('tools')
        if _tools:
            tools_menu = QMenu('Tools', self)

            for _tool in _tools:
                if _tool and _tool['name']:
                    if _tool['name'] == 'sep':
                        tools_menu.addSeparator()
                        continue

                    _cmd = _tool['cmd']

                    tools_menu.addAction(_tool['name'])

            if not tools_menu.isEmpty():
                tools_menu.triggered.connect(self._execute_tool)
                self.menu.addMenu(tools_menu)

        about_menu = QMenu('About', self)
        about_menu.addAction('Dwarf on GitHub', self._menu_github)
        about_menu.addAction('Documention', self._menu_documentation)
        about_menu.addAction('Api', self._menu_api)
        about_menu.addAction('Slack', self._menu_slack)
        about_menu.addSeparator()

        about_menu.addAction('Info', self._show_about_dlg)
        self.menu.addMenu(about_menu)

    def _show_plugin_about(self, plugin):
        plugin = self.plugin_manager.plugins[plugin]
        if plugin:
            info = plugin.__get_plugin_info__()

            version = utils.safe_read_map(info, 'version', '')
            description = utils.safe_read_map(info, 'description', '')
            author = utils.safe_read_map(info, 'author', '')
            homepage = utils.safe_read_map(info, 'homepage', '')
            license_ = utils.safe_read_map(info, 'license', '')

            utils.show_message_box(
                'Name: {0}\nVersion: {1}\nDescription: {2}\nAuthor: {3}\nHomepage: {4}\nLicense: {5}'.
                    format(plugin.name, version, description, author, homepage, license_))

    def _enable_update_menu(self):
        self._is_newer_dwarf = True

    def _update_dwarf(self):
        if self.welcome_window:
            self.welcome_window._update_dwarf()

    def _on_close_tab(self, index):
        tab_text = self.main_tabs.tabText(index)
        if tab_text:
            tab_text = tab_text.lower().replace(' ', '-')
            try:
                self._ui_elems.remove(tab_text)
            except ValueError:  # recheck ValueError: list.remove(x): x not in list
                pass
            self.main_tabs.removeTab(index)

            self.onSystemUIElementRemoved.emit(tab_text)

    def _on_dwarf_updated(self):
        self.onRestart.emit()

    def _execute_tool(self, qaction):
        if qaction:
            _tools = self.prefs.get('tools')
            if _tools:
                for _tool in _tools:
                    if _tool and _tool['name'] and _tool['name'] != 'sep':
                        if qaction.text() == _tool['name']:
                            try:
                                import subprocess
                                subprocess.Popen(_tool['cmd'], creationflags=subprocess.CREATE_NEW_CONSOLE)
                            except:
                                pass
                            break

    def _set_theme(self, qaction):
        if qaction:
            utils.set_theme(qaction.text(), self.prefs)

    def _hide_all_widgets(self):
        self.watchpoints_dwidget.hide()
        self.breakpoint_dwiget.hide()
        self.bookmarks_dwiget.hide()
        self.registers_dock.hide()
        self.console_dock.hide()
        self.backtrace_dock.hide()
        self.threads_dock.hide()

    def _show_all_widgets(self):
        self.watchpoints_dwidget.show()
        self.breakpoint_dwiget.show()
        self.bookmarks_dwiget.show()
        self.registers_dock.show()
        self.console_dock.show()
        self.backtrace_dock.show()
        self.threads_dock.show()

    def _menu_reload_core(self):
        self.dwarf.script.exports.reload()

    def _menu_debug_dwarf_js(self):
        you_know_what_to_do = json.loads(
            self.dwarf.script.exports.debugdwarfjs())
        return you_know_what_to_do

    def show_main_tab(self, name):
        name = name.lower()
        # elem doesnt exists? create it
        if name not in self._ui_elems:
            self._create_ui_elem(name)

        index = 0
        name = name.join(name.split()).lower()
        if name == 'ranges':
            index = self.main_tabs.indexOf(self.ranges_panel)
        elif name == 'search':
            index = self.main_tabs.indexOf(self.search_panel)
        elif name == 'modules':
            index = self.main_tabs.indexOf(self.modules_panel)
        elif name == 'data':
            index = self.main_tabs.indexOf(self.data_panel)
        elif name == 'jvm-tracer':
            index = self.main_tabs.indexOf(self.java_trace_panel)
        elif name == 'jvm-inspector':
            index = self.main_tabs.indexOf(self.java_inspector_panel)
        elif name == 'jvm-debugger':
            index = self.main_tabs.indexOf(self.java_explorer_panel)
        elif name == 'objc-inspector':
            index = self.main_tabs.indexOf(self.objc_inspector_panel)
        elif name == 'smali':
            index = self.main_tabs.indexOf(self.smali_panel)

        self.main_tabs.setCurrentIndex(index)

    def jump_to_address(self, ptr, view=0, show_panel=True):
        if show_panel:
            self.show_main_tab('debug')
        self.debug_panel.jump_to_address(ptr, view=view)

    @pyqtSlot(name='mainMenuGitHub')
    def _menu_github(self):
        QDesktopServices.openUrl(QUrl('https://github.com/iGio90/Dwarf'))

    @pyqtSlot(name='mainMenuApi')
    def _menu_api(self):
        QDesktopServices.openUrl(QUrl('https://igio90.github.io/Dwarf/'))

    @pyqtSlot(name='mainMenuDocumentation')
    def _menu_documentation(self):
        QDesktopServices.openUrl(QUrl('http://www.giovanni-rocca.com/dwarf/'))

    @pyqtSlot(name='mainMenuSlack')
    def _menu_slack(self):
        QDesktopServices.openUrl(
            QUrl('https://join.slack.com/t/resecret/shared_invite'
                 '/enQtMzc1NTg4MzE3NjA1LTlkNzYxNTIwYTc2ZTYyOWY1MT'
                 'Q1NzBiN2ZhYjQwYmY0ZmRhODQ0NDE3NmRmZjFiMmE1MDYwN'
                 'WJlNDVjZDcwNGE'))

    def _show_about_dlg(self):
        about_dlg = AboutDialog(self)
        about_dlg.show()

    def _create_ui_elem(self, elem):
        elem = elem.lower()

        if not isinstance(elem, str):
            return

        if elem not in self._ui_elems:
            self._ui_elems.append(elem)

        elem_wiget = None

        if elem == 'watchpoints':
            from dwarf_debugger.ui.session_widgets.watchpoints import WatchpointsWidget
            self.watchpoints_dwidget = QDockWidget('Watchpoints', self)
            self.watchpoints_panel = WatchpointsWidget(self)
            # dont respond to dblclick mem cant be shown
            # self.watchpoints_panel.onItemDoubleClicked.connect(
            #    self._on_watchpoint_clicked)
            self.watchpoints_panel.onItemRemoved.connect(
                self._on_watchpoint_removeditem)
            self.watchpoints_panel.onItemAdded.connect(self._on_watchpoint_added)
            self.watchpoints_dwidget.setWidget(self.watchpoints_panel)
            self.watchpoints_dwidget.setObjectName('WatchpointsWidget')
            self.addDockWidget(Qt.LeftDockWidgetArea, self.watchpoints_dwidget)
            self.view_menu.addAction(self.watchpoints_dwidget.toggleViewAction())
            elem_wiget = self.watchpoints_panel
        elif elem == 'breakpoints':
            from dwarf_debugger.ui.session_widgets.breakpoints import BreakpointsWidget
            self.breakpoint_dwiget = QDockWidget('breakpoint', self)
            self.breakpoints_panel = BreakpointsWidget(self)
            self.breakpoints_panel.onBreakpointRemoved.connect(self._on_breakpoint_removed)
            self.breakpoint_dwiget.setWidget(self.breakpoints_panel)
            self.breakpoint_dwiget.setObjectName('breakpointWidget')
            self.addDockWidget(Qt.LeftDockWidgetArea, self.breakpoint_dwiget)
            self.view_menu.addAction(self.breakpoint_dwiget.toggleViewAction())
            elem_wiget = self.breakpoints_panel
        elif elem == 'bookmarks':
            from dwarf_debugger.ui.session_widgets.bookmarks import BookmarksWidget
            self.bookmarks_dwiget = QDockWidget('Boomarks', self)
            self.bookmarks_panel = BookmarksWidget(self)
            self.bookmarks_dwiget.setWidget(self.bookmarks_panel)
            self.bookmarks_dwiget.setObjectName('BookmarksWidget')
            self.addDockWidget(Qt.LeftDockWidgetArea, self.bookmarks_dwiget)
            self.view_menu.addAction(self.bookmarks_dwiget.toggleViewAction())
            elem_wiget = self.bookmarks_panel
        elif elem == 'registers':
            from dwarf_debugger.ui.session_widgets.context import ContextWidget
            self.registers_dock = QDockWidget('Context', self)
            self.context_panel = ContextWidget(self)
            self.registers_dock.setWidget(self.context_panel)
            self.registers_dock.setObjectName('ContextWidget')
            self.addDockWidget(Qt.RightDockWidgetArea, self.registers_dock)
            self.view_menu.addAction(self.registers_dock.toggleViewAction())
            elem_wiget = self.context_panel
        elif elem == 'debug':
            from dwarf_debugger.ui.panels.panel_debug import QDebugPanel
            self.debug_panel = QDebugPanel(self)
            self.main_tabs.addTab(self.debug_panel, 'Debug')
            elem_wiget = self.debug_panel
        elif elem == 'jvm-debugger':
            from dwarf_debugger.ui.panels.panel_java_explorer import JavaExplorerPanel
            self.java_explorer_panel = JavaExplorerPanel(self)
            self.main_tabs.addTab(self.java_explorer_panel, 'JVM debugger')
            self.main_tabs.tabBar().moveTab(
                self.main_tabs.indexOf(self.java_explorer_panel), 1)
            elem_wiget = self.java_explorer_panel
        elif elem == 'jvm-inspector':
            from dwarf_debugger.ui.panels.panel_java_inspector import JavaInspector
            self.java_inspector_panel = JavaInspector(self)
            self.main_tabs.addTab(self.java_inspector_panel, 'JVM inspector')
            elem_wiget = self.java_inspector_panel
        elif elem == 'objc-inspector':
            from dwarf_debugger.ui.panels.panel_objc_inspector import ObjCInspector
            self.objc_inspector_panel = ObjCInspector(self)
            self.main_tabs.addTab(self.objc_inspector_panel, 'ObjC inspector')
            elem_wiget = self.objc_inspector_panel
        elif elem == 'console':
            from dwarf_debugger.ui.session_widgets.console import ConsoleWidget
            self.console_dock = QDockWidget('Console', self)
            self.console_panel = ConsoleWidget(self)
            if self.dwarf_args.script and len(self.dwarf_args.script) > 0 and os.path.exists(self.dwarf_args.script):
                with open(self.dwarf_args.script, 'r') as f:
                    self.console_panel.get_js_console().script_file = self.dwarf_args.script
                    self.console_panel.get_js_console().function_content = f.read()
            self.dwarf.onLogToConsole.connect(self._log_js_output)
            self.dwarf.onLogEvent.connect(self._log_event)
            self.console_dock.setWidget(self.console_panel)
            self.console_dock.setObjectName('ConsoleWidget')
            self.addDockWidget(Qt.BottomDockWidgetArea, self.console_dock)
            self.view_menu.addAction(self.console_dock.toggleViewAction())
            elem_wiget = self.console_panel
        elif elem == 'backtrace':
            from dwarf_debugger.ui.session_widgets.backtrace import BacktraceWidget
            self.backtrace_dock = QDockWidget('Backtrace', self)
            self.backtrace_panel = BacktraceWidget(self)
            self.backtrace_dock.setWidget(self.backtrace_panel)
            self.backtrace_dock.setObjectName('BacktraceWidget')
            self.backtrace_panel.onShowMemoryRequest.connect(self._on_showmemory_request)
            self.addDockWidget(Qt.RightDockWidgetArea, self.backtrace_dock)
            self.view_menu.addAction(self.backtrace_dock.toggleViewAction())
            elem_wiget = self.backtrace_panel
        elif elem == 'threads':
            from dwarf_debugger.ui.session_widgets.threads import ThreadsWidget
            self.threads_dock = QDockWidget('Threads', self)
            self.contexts_list_panel = ThreadsWidget(self)
            self.dwarf.onThreadResumed.connect(
                self.contexts_list_panel.resume_tid)
            self.contexts_list_panel.onItemDoubleClicked.connect(
                self._manually_apply_context)
            self.threads_dock.setWidget(self.contexts_list_panel)
            self.threads_dock.setObjectName('ThreadPanel')
            self.addDockWidget(Qt.RightDockWidgetArea, self.threads_dock)
            self.view_menu.addAction(self.threads_dock.toggleViewAction())
            elem_wiget = self.contexts_list_panel
        elif elem == 'modules':
            from dwarf_debugger.ui.panels.panel_modules import ModulesPanel
            self.modules_panel = ModulesPanel(self)
            self.modules_panel.onModuleSelected.connect(
                self._on_module_dblclicked)
            self.modules_panel.onModuleFuncSelected.connect(
                self._on_modulefunc_dblclicked)
            self.modules_panel.onAddBreakpoint.connect(self._on_addmodule_breakpoint)
            self.modules_panel.onDumpBinary.connect(self._on_dump_module)
            self.main_tabs.addTab(self.modules_panel, 'Modules')
            elem_wiget = self.modules_panel
        elif elem == 'ranges':
            from dwarf_debugger.ui.panels.panel_ranges import RangesPanel
            self.ranges_panel = RangesPanel(self)
            self.ranges_panel.onItemDoubleClicked.connect(
                self._range_dblclicked)
            self.ranges_panel.onDumpBinary.connect(self._on_dump_module)
            # connect to watchpointpanel func
            self.ranges_panel.onAddWatchpoint.connect(
                self.watchpoints_panel.do_addwatchpoint_dlg)
            self.main_tabs.addTab(self.ranges_panel, 'Ranges')
            elem_wiget = self.ranges_panel
        elif elem == 'search':
            from dwarf_debugger.ui.panels.panel_search import SearchPanel
            self.search_panel = SearchPanel(self)
            self.main_tabs.addTab(self.search_panel, 'Search')
            elem_wiget = self.search_panel
        elif elem == 'data':
            from dwarf_debugger.ui.panels.panel_data import DataPanel
            self.data_panel = DataPanel(self)
            self.main_tabs.addTab(self.data_panel, 'Data')
            elem_wiget = self.data_panel
        elif elem == 'jvm-tracer':
            from dwarf_debugger.ui.panels.panel_java_trace import JavaTracePanel
            self.java_trace_panel = JavaTracePanel(self)
            self.main_tabs.addTab(self.java_trace_panel, 'JVM tracer')
            elem_wiget = self.java_trace_panel
        elif elem == 'smali':
            from dwarf_debugger.ui.panels.panel_smali import SmaliPanel
            self.smali_panel = SmaliPanel()
            self.main_tabs.addTab(self.smali_panel, 'Smali')
            elem_wiget = self.smali_panel
        else:
            print('no handler for elem: ' + elem)

        if elem_wiget is not None:
            self.onSystemUIElementCreated.emit(elem, elem_wiget)

        # TODO: remove add @2x
        for item in self.findChildren(QDockWidget):
            if item:
                if 'darwin' in sys.platform:
                    item.setStyleSheet(
                        'QDockWidget::title { padding-left:-30px; }'
                    )

    def set_status_text(self, txt):
        self.statusbar.showMessage(txt)

    # ************************************************************************
    # **************************** Properties ********************************
    # ************************************************************************
    @property
    def disassembly(self):
        return self.asm_panel

    @property
    def backtrace(self):
        return self.backtrace_panel

    @property
    def console(self):
        return self.console_panel

    @property
    def context(self):
        return self.context_panel

    @property
    def threads(self):
        return self.contexts_list_panel

    @property
    def ftrace(self):
        return self.ftrace_panel

    @property
    def breakpoint(self):
        return self.breakpoints_panel

    @property
    def java_inspector(self):
        return self.java_inspector_panel

    @property
    def objc_inspector(self):
        return self.objc_inspector_panel

    @property
    def java_explorer(self):
        return self.java_explorer_panel

    @property
    def modules(self):
        return self.modules_panel

    @property
    def ranges(self):
        return self.ranges_panel

    @property
    def watchpoints(self):
        return self.watchpoints_panel

    @property
    def dwarf(self):
        if self.session_manager.session is not None:
            return self.session_manager.session.dwarf
        else:
            return None

    @property
    def ui_elements(self):
        return self._ui_elems

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    # session handlers
    def _start_session(self, session_type, session_data=None):
        if self.welcome_window is not None:
            self.welcome_window.close()
        try:
            self.session_manager.create_session(
                session_type, session_data=session_data)
        except Exception as e:
            if self.welcome_window:
                utils.show_message_box(str(e))

    def _restore_session(self, session_data):
        if 'session' in session_data:
            session_type = session_data['session']
            self.dwarf_args.any = session_data['package']
            self._start_session(session_type, session_data=session_data)

    def session_created(self):
        # session init done create ui for it
        session = self.session_manager.session
        self._setup_main_menu()
        for ui_elem in session.session_ui_sections:
            ui_elem = ui_elem.join(ui_elem.split()).lower()
            self._create_ui_elem(ui_elem)

        self.dwarf.onProcessAttached.connect(self._on_attached)
        self.dwarf.onProcessDetached.connect(self._on_detached)
        self.dwarf.onScriptLoaded.connect(self._on_script_loaded)

        self.dwarf.onSetRanges.connect(self._on_setranges)
        self.dwarf.onSetModules.connect(self._on_setmodules)

        self.dwarf.onAddNativeBreakpoint.connect(self._on_add_breakpoint)
        self.dwarf.onApplyContext.connect(self._apply_context)
        self.dwarf.onThreadResumed.connect(self.on_tid_resumed)
        self.dwarf.onHitModuleInitializationBreakpoint.connect(self._on_hit_module_initialization_breakpoint)

        self.dwarf.onSetData.connect(self._on_set_data)

        self.session_manager.start_session(self.dwarf_args)
        ui_state = self.q_settings.value('dwarf_ui_state')
        if ui_state:
            self.restoreGeometry(ui_state)
        window_state = self.q_settings.value('dwarf_ui_window', self.saveState())
        if window_state:
            self.restoreState(window_state)

        self.showMaximized()

    def session_stopped(self):
        self.menu.clear()

        self.main_tabs.clear()

        # actually we need to kill this. needs a refactor
        if self.java_trace_panel is not None:
            self.java_trace_panel = None

        for elem in self._ui_elems:
            if elem == 'watchpoints':
                self.watchpoints_panel.clear_list()
                self.watchpoints_panel.close()
                self.watchpoints_panel = None
                self.removeDockWidget(self.watchpoints_dwidget)
                self.watchpoints_dwidget = None
            elif elem == 'breakpoints':
                self.breakpoints_panel.close()
                self.breakpoints_panel = None
                self.removeDockWidget(self.breakpoint_dwiget)
                self.breakpoint_dwiget = None
            elif elem == 'registers':
                self.context_panel.close()
                self.context_panel = None
                self.removeDockWidget(self.registers_dock)
                self.registers_dock = None
            elif elem == 'debug':
                self.debug_panel.close()
                self.debug_panel = None
                self.main_tabs.removeTab(0)
                # self.main_tabs
            elif elem == 'jvm-debugger':
                self.java_explorer_panel.close()
                self.java_explorer_panel = None
                self.removeDockWidget(self.watchpoints_dwidget)
            elif elem == 'console':
                self.console_panel.close()
                self.console_panel = None
                self.removeDockWidget(self.console_dock)
                self.console_dock = None
            elif elem == 'backtrace':
                self.backtrace_panel.close()
                self.backtrace_panel = None
                self.removeDockWidget(self.backtrace_dock)
            elif elem == 'threads':
                self.contexts_list_panel.close()
                self.contexts_list_panel = None
                self.removeDockWidget(self.threads_dock)
                self.threads_dock = None
            elif elem == 'bookmarks':
                self.bookmarks_panel.close()
                self.bookmarks_panel = None
                self.removeDockWidget(self.bookmarks_dwiget)
                self.bookmarks_dwiget = None

        self._initialize_ui_elements()

    def session_closed(self):
        self._initialize_ui_elements()
        self.hide()
        if self.welcome_window:
            self.welcome_window.exec()
        else:
            if self.dwarf_args.any != '':
                self.close()

    # ui handler
    def closeEvent(self, event):
        """ Window closed
            save stuff or whatever at exit

            detaches dwarf
        """
        if self.session_manager.session:
            self.session_manager.session.stop()

        # save windowstuff
        self.q_settings.setValue('dwarf_ui_state', self.saveGeometry())
        self.q_settings.setValue('dwarf_ui_window', self.saveState())

        if self.dwarf:
            try:
                self.dwarf.detach()
            except:
                pass
        super().closeEvent(event)

    def _on_watchpoint_clicked(self, ptr):
        """ Address in Watchpoint/Breakpointpanel was clicked
            show Memory
        """
        if '.' in ptr:  # java_breakpoint
            file_path = ptr.replace('.', os.path.sep)
        else:
            self.jump_to_address(ptr)

    def _on_watchpoint_added(self, ptr):
        """ Watchpoint Entry was added
        """
        try:
            # set highlight
            self.debug_panel.memory_panel.add_highlight(
                HighLight('watchpoint', ptr, self.dwarf.pointer_size))
        except HighlightExistsError:
            pass

    def _on_watchpoint_removeditem(self, ptr):
        """ Watchpoint Entry was removed
            remove highlight too
        """
        self.debug_panel.memory_panel.remove_highlight(ptr)

    def _on_module_dblclicked(self, data):
        """ Module in ModulePanel was doubleclicked
        """
        addr, size = data
        addr = utils.parse_ptr(addr)
        self.jump_to_address(addr)

    def _on_modulefunc_dblclicked(self, ptr):
        """ Function in ModulePanel was doubleclicked
        """
        ptr = utils.parse_ptr(ptr)
        self.jump_to_address(ptr)

    def _on_dump_module(self, data):
        """ DumpBinary MenuItem in ModulePanel was selected
        """
        ptr, size = data
        ptr = utils.parse_ptr(ptr)
        size = int(size, 10)
        self.dwarf.dump_memory(ptr=ptr, length=size)

    def _range_dblclicked(self, ptr):
        """ Range in RangesPanel was doubleclicked
        """
        ptr = utils.parse_ptr(ptr)
        self.jump_to_address(ptr)

    # dwarf handlers
    def _log_js_output(self, output):
        if self.console_panel is not None:
            time_prefix = True
            if len(output.split('\n')) > 1 or len(output.split('<br />')) > 1:
                time_prefix = False
            self.console_panel.get_js_console().log(output, time_prefix=time_prefix)

    def _log_event(self, output):
        if self.console_panel is not None:
            self.console_panel.get_events_console().log(output)

    def _on_setranges(self, ranges):
        """ Dwarf wants to set Ranges
            only breakpointed up to switch tab or create ui
            its connected in panel after creation
        """
        if self.ranges_panel is None:
            self.show_main_tab('ranges')
            # forward only now to panel it connects after creation
            self.ranges_panel.set_ranges(ranges)
        else:
            self.show_main_tab('ranges')

    def _on_setmodules(self, modules):
        """ Dwarf wants to set Modules
            only breakpointed up to switch tab or create ui
            its connected in panel after creation
        """
        if self.modules_panel is None:
            self._create_ui_elem('modules')
            self.modules_panel.set_modules(modules)
        else:
            self.show_main_tab('modules')

    def _manually_apply_context(self, context):
        """
        perform additional operation if the context has been manually applied from the context list
        """
        self._apply_context(context, manual=True)

    def _on_hit_module_initialization_breakpoint(self, data):
        if self.debug_panel.memory_panel.number_of_lines() == 0:
            data = data[1]
            module_base = int(data['moduleBase'], 16)
            self.jump_to_address(module_base)

    def _apply_context(self, context, manual=False):
        # update current context tid
        # this should be on top as any further api from js needs to be executed on that thread
        reason = context['reason']
        is_initial_setup = reason == -1
        if manual or (self.dwarf.context_tid and not is_initial_setup):
            self.dwarf.context_tid = context['tid']

        if is_initial_setup:
            self.debug_panel.on_context_setup()

        if 'context' in context:
            if not manual:
                self.threads.add_context(context)

            is_java = context['is_java']
            if is_java:
                if self.java_explorer_panel is None:
                    self._create_ui_elem('jvm-debugger')
                self.context_panel.set_context(context['ptr'], 1, context['context'])
                self.java_explorer_panel.init()
                self.show_main_tab('jvm-debugger')
            else:
                self.context_panel.set_context(context['ptr'], 0, context['context'])

                if reason == 0:
                    if 'pc' in context['context']:
                        if self.debug_panel.disassembly_panel.number_of_lines() == 0 or manual:
                            self.jump_to_address(context['context']['pc']['value'], view=1)
                elif reason == 3:
                    # step
                    # we make the frontend believe we are in the real step pc instead of the frida space
                    context['context']['pc'] = context['ptr']
                    if 'rip' in context['context']:
                        context['context']['rip'] = context['ptr']

                    self.jump_to_address(context['ptr'], view=1)

        if 'backtrace' in context:
            self.backtrace_panel.set_backtrace(context['backtrace'])

    def _on_add_breakpoint(self, breakpoint):
        try:
            # set highlight
            ptr = breakpoint.get_target()
            ptr = utils.parse_ptr(ptr)
            self.debug_panel.memory_panel.add_highlight(
                HighLight('breakpoint', ptr, self.dwarf.pointer_size))
        except HighlightExistsError:
            pass

    def _on_breakpoint_removed(self, ptr):
        ptr = utils.parse_ptr(ptr)
        self.debug_panel.memory_panel.remove_highlight(ptr)

    def _on_addmodule_breakpoint(self, data):
        ptr, name = data
        self.dwarf.breakpoint_native(input_=ptr)

    def on_tid_resumed(self, tid):
        if self.dwarf:
            if self.dwarf.context_tid == tid:
                # clear backtrace
                if 'backtrace' in self._ui_elems:
                    if self.backtrace_panel is not None:
                        self.backtrace_panel.clear()

                # remove thread
                if 'threads' in self._ui_elems:
                    if self.contexts_list_panel is not None:
                        self.contexts_list_panel.resume_tid(tid)

                # clear registers
                if 'registers' in self._ui_elems:
                    if self.context_panel is not None:
                        self.context_panel.clear()

                # clear jvm explorer
                if 'jvm-debugger' in self._ui_elems:
                    if self.java_explorer_panel is not None:
                        self.java_explorer_panel.clear_panel()

                # invalidate dwarf context tid
                self.dwarf.context_tid = 0

    def _on_set_data(self, data):
        if not isinstance(data, list):
            return

        if self.data_panel is None:
            self.show_main_tab('data')

        if self.data_panel is not None:
            self.data_panel.append_data(data[0], data[1], data[2])

    def show_progress(self, text):
        self.progressbar.setVisible(True)
        self.set_status_text(text)

    def hide_progress(self):
        self.progressbar.setVisible(False)
        self.set_status_text('')

    def _on_attached(self, data):
        self.setWindowTitle('Dwarf - Attached to %s (%s)' % (data[1], data[0]))

    def _on_detached(self, data):
        reason = data[1]

        if reason == 'application-requested':
            if self.session_manager.session:
                self.session_manager.session.stop()
            return 0

        if self.dwarf is not None:
            ret = QDialogDetached.show_dialog(self.dwarf, data[0], data[1], data[2])
            if ret == 0:
                self.dwarf.restart_proc()
            elif ret == 1:
                self.session_manager.session.stop()

        return 0

    def _on_script_loaded(self):
        # restore the loaded session if any
        self.session_manager.restore_session()

    def on_add_bookmark(self, ptr):
        """
        provide ptr as int
        """
        if self.bookmarks_panel is not None:
            self.bookmarks_panel._create_bookmark(ptr=hex(ptr))

    def _on_showmemory_request(self, ptr):
        # its simple ptr show in memorypanel
        if isinstance(ptr, str):
            ptr = utils.parse_ptr(ptr)
            self.jump_to_address(ptr, 0)

        elif isinstance(ptr, list):
            # TODO: extend
            caller, ptr = ptr
            ptr = utils.parse_ptr(ptr)
            if caller == 'backtrace' or caller == 'bt':
                # jumpto in disasm
                self.jump_to_address(ptr, 1)
