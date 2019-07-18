class Database:

    def __init__(self):
        self.modules_info = {}

    def get_module_info(self, address):
        address = self.sanify_address(address)
        if address in self.modules_info:
            return self.modules_info[address]
        return None

    def put_module_info(self, address, module_info):
        address = self.sanify_address(address)
        self.modules_info[address] = module_info
        return module_info

    def sanify_address(self, address):
        hex_adr = address
        if isinstance(hex_adr, int):
            hex_adr = hex(hex_adr)
        return hex_adr.lower()
