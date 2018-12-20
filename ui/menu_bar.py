import json

from PyQt5.QtWidgets import QAction, QFileDialog


class MenuBar(object):
    def __init__(self, app_window):
        self.app_window = app_window
        self.menu = app_window.menuBar()

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
                    self.app_window.get_app_instance().get_hooks_panel().hook_native(hook)
                for hook in session['java']:
                    self.app_window.get_app_instance().get_hooks_panel().hook_java(hook)
                for hook in session['onloads']:
                    self.app_window.get_app_instance().get_hooks_panel().hook_onload(hook)
                for var in session['vars']:
                    self.app_window.get_app_instance().get_vars_panel().insert_var(var)

    def handler_session_save(self):
        r = QFileDialog.getSaveFileName()
        if len(r) > 0 and len(r[0]) > 0:
            hooks = []
            for hook in self.app_window.get_app_instance().get_hooks_panel().get_hooks():
                hooks.append(self.app_window.get_app_instance().get_hooks_panel().get_hooks()[hook].get_input())
            java_hooks = []
            for hook in self.app_window.get_app_instance().get_hooks_panel().get_java_hooks():
                java_hooks.append(self.app_window.get_app_instance().get_hooks_panel().get_java_hooks()[hook].get_input())
            onload_hooks = []
            for hook in self.app_window.get_app_instance().get_hooks_panel().get_onloads():
                onload_hooks.append(self.app_window.get_app_instance().get_hooks_panel().get_onloads()[hook].get_input())
            vars = []
            for var in self.app_window.get_app_instance().get_vars_panel().get_vars():
                vars.append(self.app_window.get_app_instance().get_vars_panel().get_vars()[var].get_input())
            session = {
                'natives': hooks,
                'java': java_hooks,
                'onloads': onload_hooks,
                'vars': vars
            }
            with open(r[0], 'w') as f:
                f.write(json.dumps(session))
