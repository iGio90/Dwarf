from PyQt5.QtWidgets import QAction


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

    def handler_restart(self):
        self.app_window.get_app_instance().restart()

    def handler_resume(self):
        self.app_window.get_app_instance().resume()
