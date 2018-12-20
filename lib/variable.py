class Variable(object):
    def __init__(self, key, value, type, input):
        self.key = key
        self.value = value
        self.type = type
        self.input = input

    def get_key(self):
        return self.key

    def get_input(self):
        return self.input

    def get_type(self):
        return self.type

    def get_value(self):
        return self.value
