class Watchpoint:
    def __init__(self, address, flags):
        self.address = address
        self.flags = flags
        self.debug_symbol = None

    def set_debug_symbol(self, symbol):
        self.debug_symbol = symbol
