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

import frida

from lib import utils
from lib.core import Dwarf
from lib.prefs import Prefs

from PyQt5 import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *  # QIcon, QFontDatabase
from PyQt5.QtWidgets import *

from ui.ui_welcome import WelcomeUi

from lib.session_manager import SessionManager

from ui.welcome_window import WelcomeDialog
from ui.hex_edit import HighLight, HighlightExistsError
from ui.panel_trace import TraceEvent


class AppWindow(QMainWindow):
    onRestart = pyqtSignal(name='onRestart')

    def __init__(self, dwarf_args, flags=None):
        super(AppWindow, self).__init__(flags)

        self.dwarf_args = dwarf_args

        self.session_manager = SessionManager(self)
        self.session_manager.sessionCreated.connect(self.session_created)
        self.session_manager.sessionStopped.connect(self.session_stopped)
        self.session_manager.sessionClosed.connect(self.session_closed)

        self.menu = self.menuBar()
        self._is_newer_dwarf = False
        self.view_menu = None

        self.asm_panel = None
        self.backtrace_panel = None
        self.console_panel = None
        self.context_panel = None
        self.contexts_list_panel = None
        self.data_panel = None
        self.emulator_panel = None
        self.ftrace_panel = None
        self.hooks_panel = None
        self.smali_panel = None
        self.java_inspector_panel = None
        self.java_explorer_panel = None
        self.java_trace_panel = None
        self.memory_panel = None
        self.modules_panel = None
        self.ranges_panel = None
        self.trace_panel = None
        self.watchers_panel = None
        self.welcome_window = None

        self.setWindowTitle(
            'Dwarf - A debugger for reverse engineers, crackers and security analyst'
        )

        # load external assets
        _app = QApplication.instance()

        self.remove_tmp_dir()

        # themes
        self.prefs = Prefs()
        self.set_theme(self.prefs.get('dwarf_ui_theme', 'black'))

        # set icon
        if os.name == 'nt':
            # windows stuff
            import ctypes
            try:
                # write ini to show folder with dwarficon
                folder_stuff = "[.ShellClassInfo]\nIconResource=assets\dwarf.ico,0\n[ViewState]\nMode=\nVid=\nFolderType=Generic\n"
                try:
                    with open('desktop.ini', 'w') as ini:
                        ini.writelines(folder_stuff)

                    FILE_ATTRIBUTE_HIDDEN = 0x02
                    FILE_ATTRIBUTE_SYSTEM = 0x04

                    # set fileattributes to hidden + systemfile
                    ctypes.windll.kernel32.SetFileAttributesW(
                        r'desktop.ini',
                        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)
                except PermissionError:
                    # its hidden+system already
                    pass

                # fix for showing dwarf icon in windows taskbar instead of pythonicon
                _appid = u'iGio90.dwarf.debugger'
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                    _appid)

                if os.path.exists(utils.resource_path('assets/dwarf.png')):
                    _icon = QIcon(utils.resource_path('assets/dwarf.png'))
                    _app.setWindowIcon(_icon)
                    self.setWindowIcon(_icon)
            except:
                pass
        else:
            if os.path.exists(utils.resource_path('assets/dwarf.png')):
                _icon = QIcon(utils.resource_path('assets/dwarf.png'))
                _app.setWindowIcon(_icon)
                self.setWindowIcon(_icon)

        # load font
        if os.path.exists(utils.resource_path('assets/Anton.ttf')):
            QFontDatabase.addApplicationFont('assets/Anton.ttf')
        if os.path.exists(utils.resource_path('assets/OpenSans-Regular.ttf')):
            QFontDatabase.addApplicationFont('assets/OpenSans-Regular.ttf')
            _app.setFont(QFont("OpenSans", 9, QFont.Normal))
            if os.path.exists(utils.resource_path('assets/OpenSans-Bold.ttf')):
                QFontDatabase.addApplicationFont('assets/OpenSans-Bold.ttf')

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
        self.main_tabs.setAutoFillBackground(True)
        self.setCentralWidget(self.main_tabs)

        if self.dwarf_args.package is None:
            self.welcome_window = WelcomeDialog(self)
            self.welcome_window.setModal(True)
            self.welcome_window.onIsNewerVersion.connect(self._enable_update_menu)
            self.welcome_window.onUpdateComplete.connect(self._on_dwarf_updated)
            self.welcome_window.setWindowTitle(
                'Welcome to Dwarf - A debugger for reverse engineers, crackers and security analyst'
            )
            self.welcome_window.onSessionSelected.connect(self._start_session)
            # wait for welcome screen
            self.hide()
            self.welcome_window.show()
        else:
            if dwarf_args.package is not None:
                if dwarf_args.type is None:
                    # no device given check if package is local path
                    if os.path.exists(dwarf_args.package):
                        print('* Starting new LocalSession')
                        self._start_session('local')
                    else:
                        print('use -t to set sessiontype')
                        exit(0)
                else:
                    print('* Starting new Session')
                    self._start_session(dwarf_args.type)

    def _setup_main_menu(self):
        self.menu = self.menuBar()
        dwarf_menu = QMenu('Dwarf', self)
        if self._is_newer_dwarf:
            dwarf_menu.addAction('Update', self._update_dwarf)
        dwarf_menu.addAction('Exit', self.session_closed)
        self.menu.addMenu(dwarf_menu)

        session = self.session_manager.session
        if session is not None:
            session_menu = session.main_menu
            if isinstance(session_menu, list):
                for menu in session_menu:
                    self.menu.addMenu(menu)
            else:
                self.menu.addMenu(session_menu)

        self.view_menu = QMenu('View', self)
        theme = QMenu('Theme', self.view_menu)
        theme.addAction('Black')
        theme.addAction('Black2')
        theme.addAction('Dark')
        theme.addAction('Light')
        theme.triggered.connect(self._set_theme)
        self.view_menu.addMenu(theme)
        self.view_menu.addSeparator()
        self.menu.addMenu(self.view_menu)

        about_menu = QMenu('About', self)
        about_menu.addAction('Dwarf on GitHub', self._menu_github)
        about_menu.addAction('Documention', self._menu_documentation)
        about_menu.addAction('Slack', self._menu_slack)
        about_menu.addSeparator()
        about_menu.addAction('Info')
        self.menu.addMenu(about_menu)

    def _enable_update_menu(self):
        self._is_newer_dwarf = True

    def _update_dwarf(self):
        if self.welcome_window:
            self.welcome_window._update_dwarf()

    def _on_dwarf_updated(self):
        self.onRestart.emit()

    def remove_tmp_dir(self):
        if os.path.exists('.tmp'):
            for root, dirs, files in os.walk('.tmp', topdown=False):
                for name in files:
                    os.remove(os.path.join(root, name))
                for name in dirs:
                    os.rmdir(os.path.join(root, name))
            os.rmdir(root)

    def _set_theme(self, qaction):
        if qaction:
            self.set_theme(qaction.text())

    def show_main_tab(self, name):
        index = 0
        name = name.join(name.split()).lower()
        if name == 'memory':
            index = self.main_tabs.indexOf(self.memory_panel)
        elif name == 'ranges':
            index = self.main_tabs.indexOf(self.ranges_panel)
        elif name == 'modules':
            index = self.main_tabs.indexOf(self.modules_panel)
        elif name == 'disassembly':
            index = self.main_tabs.indexOf(self.asm_panel)
        elif name == 'trace':
            index = self.main_tabs.indexOf(self.trace_panel)
        elif name == 'data':
            index = self.main_tabs.indexOf(self.data_panel)
        elif name == 'emulator':
            index = self.main_tabs.indexOf(self.emulator_panel)
        elif name == 'java-trace':
            index = self.main_tabs.indexOf(self.java_trace_panel)
        elif name == 'java-inspector':
            index = self.main_tabs.indexOf(self.java_inspector_panel)
        elif name == 'smali':
            index = self.main_tabs.indexOf(self.smali_panel)

        self.main_tabs.setCurrentIndex(index)

    @pyqtSlot(name='mainMenuGitHub')
    def _menu_github(self):
        QDesktopServices.openUrl(QUrl('https://github.com/iGio90/Dwarf'))

    @pyqtSlot(name='mainMenuDocumentation')
    def _menu_documentation(self):
        QDesktopServices.openUrl(QUrl('https://igio90.github.io/Dwarf/'))

    @pyqtSlot(name='mainMenuSlack')
    def _menu_slack(self):
        QDesktopServices.openUrl(
            QUrl('https://join.slack.com/t/resecret/shared_invite'
                 '/enQtMzc1NTg4MzE3NjA1LTlkNzYxNTIwYTc2ZTYyOWY1MT'
                 'Q1NzBiN2ZhYjQwYmY0ZmRhODQ0NDE3NmRmZjFiMmE1MDYwN'
                 'WJlNDVjZDcwNGE'))

    def _create_ui_elem(self, elem):
        if elem == 'watchers':
            from ui.panel_watchers import WatchersPanel
            self.watchers_dwidget = QDockWidget('Watchers', self)
            self.watchers_panel = WatchersPanel(self)
            # dont respond to dblclick mem cant be shown
            # self.watchers_panel.onItemDoubleClicked.connect(
            #    self._on_watcher_clicked)
            self.watchers_panel.onItemRemoved.connect(
                self._on_watcher_removeditem)
            self.watchers_panel.onItemAdded.connect(
                self._on_watcher_added)
            self.watchers_dwidget.setWidget(self.watchers_panel)
            self.watchers_dwidget.setObjectName('WatchersPanel')
            self.addDockWidget(Qt.LeftDockWidgetArea, self.watchers_dwidget)
            self.view_menu.addAction(self.watchers_dwidget.toggleViewAction())
        elif elem == 'hooks':
            from ui.panel_hooks import HooksPanel
            self.hooks_dwiget = QDockWidget('Hooks', self)
            self.hooks_panel = HooksPanel(self)
            self.hooks_panel.onShowMemoryRequest.connect(self._on_watcher_clicked)
            self.hooks_panel.onHookRemoved.connect(self._on_hook_removed)
            self.hooks_dwiget.setWidget(self.hooks_panel)
            self.hooks_dwiget.setObjectName('HooksPanel')
            self.addDockWidget(Qt.LeftDockWidgetArea, self.hooks_dwiget)
            self.view_menu.addAction(self.hooks_dwiget.toggleViewAction())
        elif elem == 'registers':
            from ui.panel_context import ContextPanel
            self.registers_dock = QDockWidget('Context', self)
            self.context_panel = ContextPanel(self)
            self.registers_dock.setWidget(self.context_panel)
            self.registers_dock.setObjectName('ContextsPanel')
            self.addDockWidget(Qt.RightDockWidgetArea, self.registers_dock)
            self.view_menu.addAction(self.registers_dock.toggleViewAction())
        elif elem == 'memory':
            from ui.panel_memory import MemoryPanel
            self.memory_panel = MemoryPanel(self)
            self.memory_panel.onShowDisassembly.connect(
                self._disassemble_range)
            self.memory_panel.dataChanged.connect(self._on_memory_modified)
            self.memory_panel.statusChanged.connect(self.set_status_text)
            self.main_tabs.addTab(self.memory_panel, 'Memory')
        elif elem == 'javaexplorer':
            from ui.panel_java_explorer import JavaExplorerPanel
            self.java_explorer_panel = JavaExplorerPanel(self)
            self.main_tabs.addTab(self.java_explorer_panel, 'JavaExplorer')
        elif elem == 'java-inspector':
            from ui.panel_java_inspector import JavaInspector
            self.java_inspector_panel = JavaInspector(self)
            self.main_tabs.addTab(self.java_inspector_panel, 'Java Inspector')
        elif elem == 'console':
            from ui.panel_console import ConsolePanel
            self.console_dock = QDockWidget('Console', self)
            self.console_panel = ConsolePanel(self)
            self.dwarf.onLogToConsole.connect(self._log_js_output)
            self.console_dock.setWidget(self.console_panel)
            self.console_dock.setObjectName('ConsolePanel')
            self.addDockWidget(Qt.BottomDockWidgetArea, self.console_dock)
            self.view_menu.addAction(self.console_dock.toggleViewAction())
        elif elem == 'backtrace':
            from ui.panel_backtrace import BacktracePanel
            self.backtrace_panel = BacktracePanel(self)
            # splitter.addWidget(self.backtrace_panel)
        elif elem == 'threads':
            from ui.panel_contexts_list import ContextsListPanel
            self.threads_dock = QDockWidget('Threads', self)
            self.contexts_list_panel = ContextsListPanel(self)
            self.dwarf.onThreadResumed.connect(self.contexts_list_panel.resume_tid)
            self.contexts_list_panel.onItemDoubleClicked.connect(self._apply_context)
            self.threads_dock.setWidget(self.contexts_list_panel)
            self.threads_dock.setObjectName('ThreadPanel')
            self.addDockWidget(Qt.RightDockWidgetArea, self.threads_dock)
            self.view_menu.addAction(self.threads_dock.toggleViewAction())
        elif elem == 'modules':
            from ui.panel_modules import ModulesPanel
            self.modules_panel = ModulesPanel(self)
            self.modules_panel.onModuleSelected.connect(
                self._on_module_dblclicked)
            self.modules_panel.onModuleFuncSelected.connect(
                self._on_modulefunc_dblclicked)
            self.modules_panel.onAddHook.connect(self._on_addmodule_hook)
            self.modules_panel.onDumpBinary.connect(self._on_dumpmodule)
            self.main_tabs.addTab(self.modules_panel, 'Modules')
        elif elem == 'ranges':
            from ui.panel_ranges import RangesPanel
            self.ranges_panel = RangesPanel(self)
            self.ranges_panel.onItemDoubleClicked.connect(self._range_dblclicked)
            self.ranges_panel.onDumpBinary.connect(self._on_dumpmodule)
            # connect to watcherpanel func
            self.ranges_panel.onAddWatcher.connect(self.watchers_panel.do_addwatcher_dlg)
            self.main_tabs.addTab(self.ranges_panel, 'Ranges')
        elif elem == 'data':
            from ui.panel_data import DataPanel
            self.data_panel = DataPanel(self)
            self.main_tabs.addTab(self.data_panel, 'Data')
        elif elem == 'trace':
            from ui.panel_trace import TracePanel
            self.trace_panel = TracePanel(self)
            self.main_tabs.addTab(self.trace_panel, 'Trace')
        elif elem == 'disassembly':
            from ui.disasm_view import DisassemblyView
            self.asm_panel = DisassemblyView(self)
            self.asm_panel.onShowMemoryRequest.connect(self._on_disasm_showmem)
            self.main_tabs.addTab(self.asm_panel, 'Disassembly')
        elif elem == 'emulator':
            from ui.panel_emulator import EmulatorPanel
            self.emulator_panel = EmulatorPanel(self)
            self.main_tabs.addTab(self.emulator_panel, 'Emulator')
        elif elem == 'java-trace':
            from ui.panel_java_trace import JavaTracePanel
            self.java_trace_panel = JavaTracePanel(self)
            self.main_tabs.addTab(self.java_trace_panel, 'Java-Trace')
        elif elem == 'smali':
            from ui.panel_smali import SmaliPanel
            self.smali_panel = SmaliPanel()
            self.main_tabs.addTab(self.smali_panel, 'Smali')
        else:
            print('no handler for elem: ' + elem)

    def set_theme(self, theme):
        if theme:
            theme = theme.replace(os.pardir, '').replace('.', '')
            theme = theme.join(theme.split()).lower()
            theme_style = 'assets/' + theme + '_style.qss'
            if not os.path.exists(utils.resource_path(theme_style)):
                return

            self.prefs.put('dwarf_ui_theme', theme)

            try:
                _app = QApplication.instance()
                with open(theme_style) as stylesheet:
                    _app.setStyleSheet(_app.styleSheet() + '\n'
                                       + stylesheet.read())
            except Exception as e:
                pass
                #err = self.dwarf.spawn(dwarf_args.package, dwarf_args.script)

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
    def emulator(self):
        return self.emulator_panel

    @property
    def ftrace(self):
        return self.ftrace_panel

    @property
    def hooks(self):
        return self.hooks_panel

    @property
    def java_inspector(self):
        return self.java_inspector_panel

    @property
    def java_explorer(self):
        return self.java_explorer_panel

    @property
    def memory(self):
        return self.memory_panel

    @property
    def modules(self):
        return self.memory_panel

    @property
    def ranges(self):
        return self.ranges_panel

    @property
    def trace(self):
        return self.trace_panel

    @property
    def watchers(self):
        return self.watchers_panel

    @property
    def dwarf(self):
        if self.session_manager.session is not None:
            return self.session_manager.session.dwarf
        else:
            return None

    # ************************************************************************
    # **************************** Handlers **********************************
    # ************************************************************************
    # session handlers
    def _start_session(self, session_type):
        if self.welcome_window is not None:
            self.welcome_window.close()
        self.session_manager.create_session(session_type)

    def session_created(self):
        # session init done create ui for it
        session = self.session_manager.session
        self._setup_main_menu()
        for ui_elem in session.session_ui_sections:
            ui_elem = ui_elem.join(ui_elem.split()).lower()
            self._create_ui_elem(ui_elem)

        self.dwarf.onAttached.connect(self._on_attached)
        # hookup
        self.dwarf.onSetRanges.connect(self._on_setranges)
        self.dwarf.onSetModules.connect(self._on_setmodules)

        self.dwarf.onAddNativeHook.connect(self._on_add_hook)
        self.dwarf.onApplyContext.connect(self._apply_context)
        self.dwarf.onThreadResumed.connect(self.on_tid_resumed)

        self.dwarf.onTraceData.connect(self._on_tracer_data)
        self.dwarf.onSetData.connect(self._on_set_data)

        self.session_manager.start_session(self.dwarf_args)
        q_settings = QSettings("dwarf_window_pos.ini", QSettings.IniFormat)
        ui_state = q_settings.value('dwarf_ui_state')
        if ui_state:
            self.restoreGeometry(ui_state)
        window_state = q_settings.value('dwarf_ui_window', self.saveState())
        if window_state:
            self.restoreState(window_state)

        self.showMaximized()

    def session_stopped(self):
        self.remove_tmp_dir()
        self.menu.clear()

        self.main_tabs.clear()

        for elem in self.session_manager.session.session_ui_sections:
            if elem == 'watchers':
                self.watchers_panel.clear_list()
                self.watchers_panel.close()
                self.watchers_panel = None
                self.removeDockWidget(self.watchers_dwidget)
                self.watchers_dwidget = None
            elif elem == 'hooks':
                self.hooks_panel.close()
                self.hooks_panel = None
                self.removeDockWidget(self.hooks_dwiget)
                self.hooks_dwiget = None
            elif elem == 'registers':
                self.context_panel.close()
                self.context_panel = None
                self.removeDockWidget(self.registers_dock)
                self.registers_dock = None
            elif elem == 'memory':
                self.memory_panel.close()
                self.memory_panel = None
                self.main_tabs.removeTab(0)
                # self.main_tabs
            elif elem == 'javaexplorer':
                self.java_explorer_panel.close()
                self.java_explorer_panel = None
                self.removeDockWidget(self.watchers_dwidget)
            elif elem == 'console':
                self.console_panel.close()
                self.console_panel = None
                self.removeDockWidget(self.console_dock)
                self.console_dock = None
            elif elem == 'backtrace':
                self.backtrace_panel.close()
                self.backtrace_panel = None
                self.removeDockWidget(self.watchers_dwidget)
            elif elem == 'threads':
                self.contexts_list_panel.close()
                self.contexts_list_panel = None
                self.removeDockWidget(self.threads_dock)
                self.threads_dock = None

    def session_closed(self):
        self.hide()
        if self.welcome_window is not None:
            self.welcome_window.exec()

        # close if it was a commandline session
        if self.welcome_window is None:
            if self.dwarf_args.package:
                self.close()

    # ui handler
    def closeEvent(self, event):
        """ Window closed
            save stuff or whatever at exit

            detaches dwarf
        """
        # save windowstuff
        q_settings = QSettings("dwarf_window_pos.ini", QSettings.IniFormat)
        q_settings.setValue('dwarf_ui_state', self.saveGeometry())
        q_settings.setValue('dwarf_ui_window', self.saveState())

        if self.dwarf:
            self.dwarf.detach()
        super().closeEvent(event)

    def _on_watcher_clicked(self, ptr):
        """ Address in Watcher/Hookpanel was clicked
            show Memory
        """
        if '.' in ptr:  # java_hook
            file_path = ptr.replace('.', os.path.sep)
            if os.path.exists('.tmp/smali/' + file_path + '.smali'):
                if self.smali_panel is None:
                    self._create_ui_elem('smali')
                self.smali_panel.set_file('.tmp/smali/' + file_path + '.smali')
                self.show_main_tab('smali')
        else:
            self.memory_panel.read_memory(ptr=ptr)
            self.show_main_tab('memory')

    def _on_disasm_showmem(self, ptr, length):
        """ Address in Disasm was clicked
            adds temphighlight for bytes from current instruction
        """
        self.memory_panel.read_memory(ptr)
        self.memory_panel.add_highlight(HighLight('attention', utils.parse_ptr(ptr), length))
        self.show_main_tab('memory')

    def _on_watcher_added(self, ptr):
        """ Watcher Entry was added
        """
        try:
            # set highlight
            self.memory_panel.add_highlight(
                HighLight('watcher', ptr, self.dwarf.pointer_size))
        except HighlightExistsError:
            pass

    def _on_watcher_removeditem(self, ptr):
        """ Watcher Entry was removed
            remove highlight too
        """
        self.memory_panel.remove_highlight(ptr)

    def _on_module_dblclicked(self, data):
        """ Module in ModulePanel was doubleclicked
        """
        addr, size = data
        addr = utils.parse_ptr(addr)
        size = int(size, 10)
        self.memory_panel.read_memory(ptr=addr, length=size)
        self.show_main_tab('Memory')

    def _on_modulefunc_dblclicked(self, ptr):
        """ Function in ModulePanel was doubleclicked
        """
        ptr = utils.parse_ptr(ptr)
        self.memory_panel.read_memory(ptr=ptr)
        self.show_main_tab('Memory')

    def _on_dumpmodule(self, data):
        """ DumpBinary MenuItem in ModulePanel was selected
        """
        ptr, size = data
        ptr = utils.parse_ptr(ptr)
        size = int(size, 10)
        self.dwarf.dump_memory(ptr=ptr, length=size)

    def _disassemble_range(self, mem_range):
        """ Disassemble MenuItem in Hexview was selected
        """
        if mem_range:
            if self.asm_panel is None:
                self._create_ui_elem('disassembly')

            if mem_range:
                self.asm_panel.disassemble(mem_range)
                self.show_main_tab('disassembly')

    def _range_dblclicked(self, ptr):
        """ Range in RangesPanel was doubleclicked
        """
        ptr = utils.parse_ptr(ptr)
        self.memory_panel.read_memory(ptr=ptr)
        self.show_main_tab('Memory')

    # dwarf handlers
    def _log_js_output(self, output):
        if self.console_panel is not None:
            self.console_panel.get_js_console().log(output)

    def _on_setranges(self, ranges):
        """ Dwarf wants to set Ranges
            only hooked up to switch tab or create ui
            its connected in panel after creation
        """
        if self.ranges_panel is None:
            self._create_ui_elem('ranges')
            # forward only now to panel it connects after creation
            self.ranges_panel.set_ranges(ranges)

        if self.ranges_panel is not None:
            self.show_main_tab('ranges')

    def _on_setmodules(self, modules):
        """ Dwarf wants to set Modules
            only hooked up to switch tab or create ui
            its connected in panel after creation
        """
        if self.modules_panel is None:
            self._create_ui_elem('modules')
            self.modules_panel.set_modules(modules)

        if self.modules_panel is not None:
            self.show_main_tab('modules')

    def _apply_context(self, context):
        if 'context' in context:
            is_java = context['is_java']
            if is_java:
                if self.java_explorer_panel is None:
                    self._create_ui_elem('javaexplorer')
                self.context_panel.set_context(context['ptr'], 1,
                                               context['context'])
                self.java_explorer_panel.set_handle_arg(-1)
                self.show_main_tab('javaexplorer')
            else:
                self.context_panel.set_context(context['ptr'], 0,
                                               context['context'])

    def _on_add_hook(self, hook):
        try:
            # set highlight
            ptr = hook.get_ptr()
            ptr = utils.parse_ptr(ptr)
            self.memory_panel.add_highlight(
                HighLight('hook', ptr, self.dwarf.pointer_size))
        except HighlightExistsError:
            pass

    def _on_hook_removed(self, ptr):
        ptr = utils.parse_ptr(ptr)
        self.memory_panel.remove_highlight(ptr)

    def _on_addmodule_hook(self, data):
        ptr, name = data
        self.dwarf.hook_native(ptr, own_input=name)

    def on_tid_resumed(self, tid):
        if self.dwarf:
            if self.dwarf.context_tid == tid:
                self.context_panel.clear()
                # self.context_panel.setRowCount(0)
                # self.backtrace_panel.setRowCount(0)
                # self.memory_panel.clear_panel()
                # if self.get_java_explorer_panel() is not None:
                #    self.get_java_explorer_panel().clear_panel()

            # self.contexts_list_panel.resume_tid(tid)

    def _on_tracer_data(self, data):
        if not data:
            return

        if self.trace_panel is None:
            self._create_ui_elem('trace')

        if self.trace_panel is not None:
            self.show_main_tab('Trace')
            self.trace_panel.start()

            trace_events_parts = data[1].split(',')
            while trace_events_parts:
                trace_event = TraceEvent(
                    trace_events_parts.pop(0),
                    trace_events_parts.pop(0),
                    trace_events_parts.pop(0),
                    trace_events_parts.pop(0)
                )
                self.trace_panel.event_queue.append(trace_event)

    def _on_set_data(self, data):
        if not isinstance(data, list):
            return

        if self.data_panel is None:
            self._create_ui_elem('data')

        if self.data_panel is not None:
            self.show_main_tab('Data')
            self.data_panel.append_data(data[0], data[1], data[2])

    def show_progress(self, text):
        self.progressbar.setVisible(True)
        self.set_status_text(text)

    def hide_progress(self):
        self.progressbar.setVisible(False)
        self.set_status_text('')

    def _on_attached(self, data):
        self.setWindowTitle('Dwarf - Attached to %s (%s)' % (data[1], data[0]))

    def _on_memory_modified(self, pos, length):
        data_pos = self.memory_panel.base + pos
        data = self.memory_panel.data[pos:pos + length]
        data = [data[0]]  # todo: strange js part

        if self.dwarf.dwarf_api('writeBytes', [data_pos, data]):
            pass
        else:
            utils.show_message_box('Failed to write Memory')
