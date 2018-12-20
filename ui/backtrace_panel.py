from PyQt5.QtWidgets import QTableWidget


class BacktracePanel(QTableWidget):
    def __init__(self, *__args):
        super().__init__(0, 3)

        self.verticalHeader().hide()
        self.setHorizontalHeaderLabels(['symbol', 'offset', 'address'])
