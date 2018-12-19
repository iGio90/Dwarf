from ui.widget_item_not_editable import NotEditableTableWidgetItem


class HookWidget(NotEditableTableWidgetItem):
    def __init__(self, *__args):
        super().__init__(*__args)

        self.hook_data = None

    def set_hook_data(self, hook_data):
        self.hook_data = hook_data

    def get_hook_data(self):
        return self.hook_data