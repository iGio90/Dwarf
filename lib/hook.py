class Hook(object):

    def __init__(self):
        self.ptr = 0
        self.widget_row = 0
        self.input = ''
        self.condition = ''
        self.logic = ''

    def set_ptr(self, ptr):
        self.ptr = ptr

    def set_input(self, input):
        self.input = input

    def set_condition(self, condition):
        self.condition = condition

    def set_logic(self, logic):
        self.logic = logic

    def set_widget_row(self, row):
        self.widget_row = row

    def get_ptr(self):
        if self.ptr == 1:
            # for java hooks, return class and method
            return self.input
        return self.ptr

    def get_input(self):
        return self.input

    def get_condition(self):
        return self.condition

    def get_logic(self):
        return self.logic

    def get_widget_row(self):
        return self.widget_row
