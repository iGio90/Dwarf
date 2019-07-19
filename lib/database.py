import os
import shutil


class Database:

    def __init__(self, dwarf):
        self.modules_info = {}
        self.ranges_info = {}

        self._ranges_path = '.ranges'
        if os.path.exists(self._ranges_path):
            shutil.rmtree(self._ranges_path)
        os.mkdir(self._ranges_path)

        dwarf.onThreadResumed.connect(self._clean_ranges_cache)

    def _clean_ranges_cache(self):
        # files will be cleaned on next db creation. to cleanup cache is enough to remove info from the map
        # we clean only ranges with writable permissions
        for range in list(self.ranges_info.keys()):
            perm = self.ranges_info[range]
            if 'w' in perm:
                del self.ranges_info[range]

    def get_module_info(self, address):
        address = self.sanify_address(address)
        if address in self.modules_info:
            return self.modules_info[address]
        return None

    def get_range_data(self, address):
        address = self.sanify_address(address)
        if address in self.ranges_info:
            cache_path = os.path.join(self._ranges_path, address)
            if os.path.exists(cache_path):
                with open(cache_path, 'rb') as f:
                    return f.read()
        return None

    def put_module_info(self, address, module_info):
        address = self.sanify_address(address)
        self.modules_info[address] = module_info
        return module_info

    def put_range_data(self, address, permissions, data):
        address = self.sanify_address(address)
        self.ranges_info[address] = permissions
        with open(os.path.join(self._ranges_path, address), 'wb') as f:
            f.write(data)

    def sanify_address(self, address):
        hex_adr = address
        if isinstance(hex_adr, int):
            hex_adr = hex(hex_adr)
        return hex_adr.lower()
