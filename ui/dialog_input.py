from PyQt5 import QtCore
from PyQt5.QtWidgets import *


class InputDialog(QDialog):
    def __init__(self, parent=None, hint=None, size=False):
        super(InputDialog, self).__init__(parent)

        layout = QVBoxLayout(self)
        if hint:
            layout.addWidget(QLabel(hint))
        self.input_widget = QLineEdit(self)
        layout.addWidget(self.input_widget)

        self.size_widget = None
        self.sub_widget = None
        if size:
            layout.addWidget(QLabel('size'))
            self.size_widget = QLineEdit(self)
            self.size_widget.setText('1024')
            layout.addWidget(self.size_widget)

            layout.addWidget(QLabel('substract'))
            self.sub_widget = QLineEdit(self)
            self.sub_widget.setText('512')
            layout.addWidget(self.sub_widget)

    def keyPressEvent(self, event):
        super(InputDialog, self).keyPressEvent(event)
        if event.key() == QtCore.Qt.Key_Return:
            self.accept()

    @staticmethod
    def input(hint=None, size=False):
        dialog = InputDialog(hint=hint, size=size)
        result = dialog.exec_()

        if size:
            return result == QDialog.Accepted, \
                   dialog.input_widget.text(), \
                   dialog.size_widget.text(), \
                   dialog.sub_widget.text()
        else:
            return result == QDialog.Accepted, \
                   dialog.input_widget.text()
