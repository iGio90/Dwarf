class Database:

    def __init__(self):
        self.modules_info = {}

    def get_module_info(self, hex_address):
        if hex_address in self.modules_info:
            return self.modules_info[hex_address]

    def put_module_info(self, hex_address, module_info):
        self.modules_info[hex_address] = module_info
        return module_info
