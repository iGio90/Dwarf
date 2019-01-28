# -*- mode: python -*-

block_cipher = None


a = Analysis(['dwarf.py'],
             pathex=['/tmp/Dwarf'],
             binaries=[],
             datas=[],
             hiddenimports=[],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)

a.datas += [('ui/dwarf.png', '/tmp/Dwarf/ui/dwarf.png','DATA')]
a.datas += [('ui/dwarf_alpha.png', '/tmp/Dwarf/ui/dwarf_alpha.png','DATA')]


exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          [],
          name='dwarf',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          runtime_tmpdir=None,
          console=True )

var m = Process.findModuleByName('libg.so');
Memory.protect(m.base, m.size, 'rwx');
var svc_send = Memory.scanSync(m.base, m.size, '14 70 9F E5 00 00 00 EF');
var svc_recv = Memory.scanSync(m.base, m.size, '49 7F A0 E3 00 00 00 EF');
Interceptor.attach(svc_send[0]['address'], function () {
    if (sw(Memory.readUShort(this.context.r1)) === 10101) {
        return 0;
    }
    return -1;
});
function sw(val) {
    return ((val & 0xFF) << 8) | ((val >> 8) & 0xFF);
}






