"""
    Dwarf - Copyright (C) 2018-2020 Giovanni Rocca (iGio90)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.
    If not, see <https://www.gnu.org/licenses/>
"""
from dwarf_debugger.lib.tool import Tool


class Trace(Tool):
    def parse_arguments(self, parser):
        parser.add_argument(
            "-n",
            "--native",
            type=str,
            help="Trace native address (0xac0b9cc0 | open | open+0x24 | libtarget.so@0x1234)"
        )

        parser.add_argument(
            "-nr",
            "--native-registers",
            type=str,
            help="Comma separated list of registers to read"
        )

        parser.add_argument(
            "-j",
            "--java",
            type=str,
            help="Trace java methods"
        )

    def get_script(self):
        if self.arguments.java is None and self.arguments.native is None:
            if self.arguments.any is None or self.arguments.any == '':
                self.arguments_parser.print_help()
                exit(2)
            print('provide a method to trace with either --native or --java')
            exit(2)

        tracer_script = None
        if self.arguments.java is not None:
            clazz = self.arguments.java.split('.')
            if len(clazz) < 2:
                print('%s not a valid class method. (android.app.Activity.onCreate)')
                exit(2)
            method = clazz[-1]
            clazz = '.'.join(clazz[:-1])
            fnc = 'hookJavaMethod'
            fmt_args = [clazz, method]
            if method == '$init':
                fnc = 'hookJavaConstructor'
                del fmt_args[-1]
            tracer_script = fnc + '''
            ('%s', function() {
                console.log(this.$className, this.method);
                for (var i=0;i<arguments.length;i++) {
                    var clazz = arguments[i].$className;
                    if (typeof clazz === 'undefined') {
                        clazz = '';
                    } else {
                        clazz = ' - ' + clazz;
                    }
                    var val = arguments[i].toString();
                    if (val.length === 0) {
                        val = "''";
                    }
                    console.log('   ', val, clazz);
                }
                console.log('');
            })
            ''' % ('.'.join(fmt_args))
        elif self.arguments.native is not None:
            target_address_str = str(self.arguments.native)
            tracer_top = ''

            def die():
                print(target_address_str, 'is not a valid native trace address. see examples --help')
                exit(2)

            def read_offset(_offset):
                if _offset.startswith('0x'):
                    try:
                        return int(_offset, 16)
                    except:
                        die()
                else:
                    try:
                        return int(_offset)
                    except:
                        die()

            if target_address_str.startswith('0x'):
                try:
                    target_address = int(target_address_str, 16)
                    tracer_top = '''
                        trace(%d);
                    ''' % target_address
                except:
                    die()
            elif '@' in target_address_str:
                target_address_str = target_address_str.split('@')
                module_name = target_address_str[0]
                offset = read_offset(target_address_str[1])
                tracer_top = '''
                    var moduleName = '%s';
                    var offset = %d;
                    var m = Process.findModuleByName(moduleName);
                    if (m === null) {
                        hookModuleInitialization(moduleName, function() {
                            removeModuleInitializationBreakpoint(moduleName);
                            m = Process.findModuleByName(moduleName);
                            trace(m.base.add(offset));
                        });
                    } else {
                        trace(m.add(offset));
                    }
                ''' % (module_name, offset)
            else:
                target_address_str = target_address_str.split('+')
                symbol_name = target_address_str[0]
                offset = 0

                if len(target_address_str) > 1:
                    offset = read_offset(target_address_str[1])

                tracer_top = '''
                    var exportName = '%s';
                    var s = Module.findExportByName(null, exportName);
                    if (s === null) {
                        console.log(exportName, 'not found in exports');
                    } else {
                        trace(s.add(%d));
                    }
                ''' % (symbol_name, offset)

            native_registers = ''
            if self.arguments.native_registers is not None:
                native_registers += self.arguments.native_registers

            tracer_script = '''
                var tracedRegisters = '%s';
                tracedRegisters = tracedRegisters.split(',');
                
                function trace(address) {
                    Interceptor.attach(address, {
                        onEnter: function() {
                            var ctx = this.context;
                            console.log('-->', this.context.pc);
                            tracedRegisters.forEach(function(register) {
                                var val = '';
                                var rVal = ctx[register];
                                if (rVal.toInt32() > 0) {
                                    try { val = rVal.readUtf8String(); } catch(err) {}
                                }
                                console.log(' ', register, rVal, val);
                            });
                        },
                        onLeave: function(retVal) {
                            console.log(' <--', retVal);
                        }
                    })
                }
            ''' % native_registers

            tracer_script += tracer_top
        return tracer_script


def main():
    Trace()
