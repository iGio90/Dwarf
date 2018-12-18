from PyQt5.QtCore import Qt

from ui.widget_item_not_editable import NotEditableTableWidgetItem


class ByteWidget(NotEditableTableWidgetItem):
    def __init__(self, *__args):
        super().__init__(*__args)
        self.value = 0

    def get_value(self):
        return self.value

    def set_value(self, value):
        self.value = value

        if self.value == 0:
            self.setForeground(Qt.gray)
