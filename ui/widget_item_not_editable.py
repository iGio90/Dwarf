from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QListWidgetItem, QTableWidgetItem


class NotEditableListWidgetItem(QListWidgetItem):
    def __init__(self, *__args):
        super().__init__(*__args)
        self.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)


class NotEditableTableWidgetItem(QTableWidgetItem):
    def __init__(self, *__args):
        super().__init__(*__args)
        self.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
