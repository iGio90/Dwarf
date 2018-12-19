from PyQt5 import QtCore
from PyQt5.QtWidgets import *


class InputMultilineDialog(QDialog):
    def __init__(self, parent=None, hint=None, input_content=''):
        super(InputMultilineDialog, self).__init__(parent)

        layout = QVBoxLayout(self)
        if hint:
            layout.addWidget(QLabel(hint))
        self.input_widget = QTextEdit(self)
        if len(input_content) > 0:
            self.input_widget.setText(input_content)
        layout.addWidget(self.input_widget)

    def keyPressEvent(self, event):
        super(InputMultilineDialog, self).keyPressEvent(event)
        if event.key() == QtCore.Qt.Key_Escape:
            self.accept()

    @staticmethod
    def input(hint=None, input_content=''):
        dialog = InputMultilineDialog(hint=hint, input_content=input_content)
        result = dialog.exec_()

        return result == QDialog.Accepted, \
               dialog.input_widget.toPlainText()
