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
