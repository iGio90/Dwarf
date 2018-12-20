from PyQt5.QtWidgets import QListWidget, QListWidgetItem

from ui.widget_item_not_editable import NotEditableListWidgetItem


class LogPanel(QListWidget):
    def __init__(self):
        super().__init__()

    def add_to_main_content_content(self, what, clear=False, scroll=False):
        if clear:
            self.clear()

        if isinstance(what, QListWidgetItem):
            self.addItem(what)
        else:
            item = NotEditableListWidgetItem(what)
            self.addItem(item)

        if scroll:
            self.scrollToBottom()
