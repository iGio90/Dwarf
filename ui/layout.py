from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QSplitter


class Layout(QSplitter):
    def __init__(self, app, *__args):
        super().__init__(*__args)

        self.app = app

    def keyPressEvent(self, event):
        pass
