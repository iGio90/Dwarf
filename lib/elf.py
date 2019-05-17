"""
Dwarf - Copyright (C) 2019 Giovanni Rocca (iGio90)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>
"""


class ProgramHeader:
    PT = {
        0x00000000: 'PT_NULL',
        0x00000001: 'PT_LOAD',
        0x00000002: 'PT_DYNAMIC',
        0x00000003: 'PT_INTERP',
        0x00000004: 'PT_NOTE',
        0x00000005: 'PT_SHLIB',
        0x00000006: 'PT_PHDR',
        0x60000000: 'PT_LOOS',
        0x6FFFFFFF: 'PT_HIOS',
        0x70000000: 'PT_LOPROC',
        0x7FFFFFFF: 'PT_HIPROC',
    }

    def __init__(self, bits, data):
        self.type = self.parse_type(data)

        len_ = int(bits / 8)

        if bits == 64:
            self.flags = int.from_bytes(data[0x4:0x8], 'little')
        else:
            self.flags = int.from_bytes(data[0x18:len_], 'little')
        _b = 0x4 if bits == 32 else 0x8
        self.p_offset = int.from_bytes(data[_b:_b + len_], 'little')
        _b = 0x08 if bits == 32 else 0x10
        self.p_vaddr = int.from_bytes(data[_b:_b + len_], 'little')
        _b = 0x0C if bits == 32 else 0x18
        self.p_paddr = int.from_bytes(data[_b:_b + len_], 'little')
        _b = 0x10 if bits == 32 else 0x20
        self.p_filesz = int.from_bytes(data[_b:_b + len_], 'little')
        _b = 0x14 if bits == 32 else 0x28
        self.p_memsz = int.from_bytes(data[_b:_b + len_], 'little')
        _b = 0x1C if bits == 32 else 0x30
        self.p_align = int.from_bytes(data[_b:_b + len_], 'little')

    def parse_type(self, data):
        val = int.from_bytes(data[:4], 'little')
        if val in self.PT:
            return self.PT[val]
        else:
            return hex(val)


class SectionHeader:
    SHT = {
        0x0: 'SHT_NULL',
        0x1: 'SHT_PROGBITS',
        0x2: 'SHT_SYMTAB',
        0x3: 'SHT_STRTAB',
        0x4: 'SHT_RELA',
        0x5: 'SHT_HASH',
        0x6: 'SHT_DYNAMIC',
        0x7: 'SHT_NOTE',
        0x8: 'SHT_NOBITS',
        0x9: 'SHT_REL',
        0x0A: 'SHT_SHLIB',
        0x0B: 'SHT_DYNSYM',
        0x0E: 'SHT_INIT_ARRAY',
        0x0F: 'SHT_FINI_ARRAY',
        0x10: 'SHT_PREINIT_ARRAY',
        0x11: 'SHT_GROUP',
        0x12: 'SHT_SYMTAB_SHNDX',
        0x13: 'SHT_NUM',
        0x60000000: 'SHT_LOOS',
    }

    def __init__(self, bits, data):
        len_ = int(bits / 8)

        self.sh_name = int.from_bytes(data[:0x4], 'little')
        self.sh_type = self.parse_type(data)
        self.flags = int.from_bytes(data[0x8:len_], 'little')
        _b = 0x0C if bits == 32 else 0x10
        self.sh_addr = int.from_bytes(data[_b:_b + len_], 'little')
        _b = 0x10 if bits == 32 else 0x18
        self.sh_offset = int.from_bytes(data[_b:_b + len_], 'little')
        _b = 0x14 if bits == 32 else 0x20
        self.sh_size = int.from_bytes(data[_b:_b + len_], 'little')
        _b = 0x18 if bits == 32 else 0x28
        self.sh_link = int.from_bytes(data[_b:_b + 4], 'little')
        _b = 0x1C if bits == 32 else 0x2C
        self.sh_info = int.from_bytes(data[_b:_b + 4], 'little')
        _b = 0x20 if bits == 32 else 0x30
        self.sh_addralign = int.from_bytes(data[_b:_b + len_], 'little')
        _b = 0x24 if bits == 32 else 0x38
        self.sh_entsize = int.from_bytes(data[_b:_b + len_], 'little')

    def parse_type(self, data):
        val = int.from_bytes(data[0x4:0x8], 'little')
        if val in self.SHT:
            return self.SHT[val]
        else:
            return hex(val)


class ELF:
    def __init__(self, data):
        self.bits = 32 if data[4] == 1 else 64

        _b = 0x1c if self.bits == 32 else 0x20
        self.e_phoff = int.from_bytes(data[_b:int(_b+self.bits/8)], 'little')
        _b = 0x20 if self.bits == 32 else 0x28
        self.e_shoff = int.from_bytes(data[_b:int(_b+_b/8)], 'little')

        _b = 0x2a if self.bits == 32 else 0x36
        self.e_phentsize = int.from_bytes(data[_b:_b+2], 'little')
        _b = 0x2c if self.bits == 32 else 0x38
        self.e_phnum = int.from_bytes(data[_b:_b+2], 'little')

        _b = 0x2e if self.bits == 32 else 0x3a
        self.e_shentsize = int.from_bytes(data[_b:_b+2], 'little')
        _b = 0x30 if self.bits == 32 else 0x3c
        self.e_shnum = int.from_bytes(data[_b:_b+2], 'little')

        elf = data[self.e_phoff:]
        self.program_headers = []
        for i in range(self.e_phnum):
            self.program_headers.append(ProgramHeader(
                self.bits, elf[i * self.e_phentsize:i * self.e_phentsize + self.e_phentsize]))
        elf = elf[self.e_shoff:]
        self.section_headers = []
        for i in range(self.e_shnum):
            self.section_headers.append(SectionHeader(
                self.bits, elf[i * self.e_shentsize:i * self.e_shentsize + self.e_shentsize]))

    @staticmethod
    def build(data):
        if data[0] == 0x7f and data[1] == 0x45 and data[2] == 0x4c and data[3] == 0x46:
            return ELF(data)
        return None
